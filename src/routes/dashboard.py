import hashlib
import logging

# FOR TESTING ONLY!!!
import os
import re
import smtplib
import ssl
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote

import mutils
import time
from apiflask import APIBlueprint
import markdown

from authz import authorize

from exceptions import ConflictError, AuthorizationError
from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    g,
)
from utils import is_valid_uuid
import cutils
import kutils
from entity import PackageEntity
from processes import PROCESS
from tasks import TASK
from tools import TOOL
from cutils import TAG, ORGANIZATION, DATASET, RESOURCE
from auth import admin_required
from backend.llmsearch import llm_search_enabled
import json


dashboard_bp = APIBlueprint("dashboard_blueprint", __name__, enable_openapi=False)

logger = logging.getLogger(__name__)


def render_stelar_template(template_name, **kwargs):
    """
    Helper function to include the S3_CONSOLE_URL in all templates.
    """
    config = current_app.config["settings"]
    # Add the S3_CONSOLE_URL to the kwargs
    kwargs["S3_CONSOLE_URL"] = config.get("S3_CONSOLE_URL", "#")
    kwargs["AVATAR"] = session.get("AVATAR", None)
    kwargs["LLM_SEARCH_ENABLED"] = config.get("LLM_SEARCH_ENABLED", False)
    kwargs["GITHUB_API"] = "https://api.github.com"
    kwargs["GITHUB_RAW"] = "https://raw.githubusercontent.com"
    return render_template(template_name, **kwargs)


# DEVELOPMENT ONLY FOR AWS CLUSTERS: Decide which partner the cluster corresponds to
def get_partner_logo():
    domain = os.getenv("KLMS_DOMAIN_NAME", "")
    PARTNER_IMAGE = None
    if domain:
        if "vista" in domain.lower():
            PARTNER_IMAGE = url_for("static", filename="logos/vista.png")
        elif "abaco" in domain.lower():
            PARTNER_IMAGE = url_for("static", filename="logos/abaco.png")
        elif "ak" in domain.lower():
            PARTNER_IMAGE = url_for("static", filename="logos/ak.png")
        else:
            PARTNER_IMAGE = url_for("static", filename="logos/arc.png")
    return PARTNER_IMAGE


def get_avatar():
    """
    Returns the URL of the user's avatar in static/avatars/ if it exists,
    otherwise returns None.
    """
    username = session.get("USER_USERNAME")
    if username:
        avatar_filename = f"{username}.png"  # Modify extension if needed.
        avatar_path = os.path.join(
            current_app.root_path, "static", "avatars", avatar_filename
        )
        if os.path.exists(avatar_path):
            return url_for("static", filename=f"avatars/{avatar_filename}")
    return None


def extract_github_repo_info(url):
    pattern = r"^https?://(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"
    match = re.match(pattern, url)
    if match:
        user, repo = match.groups()
        return user, repo
    return None


def session_required(f):
    """
    Custom decorator to check if the session is active and the token is valid.
    If the session is invalid or token is expired, redirect to login with a default message.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Retrieve token from session
        access_token = session.get("access_token")

        current_time = int(time.time())
        token_expired = (
            session.get("token_expires", 0) < current_time - 120
            or session.get("refresh_expires", 0) < current_time - 120
        )
        access_token = session.get("access_token")

        # If token expired or inactive, attempt to refresh it atomically
        if (
            token_expired
            or not access_token
            or not kutils.is_token_active(access_token)
        ):
            try:
                try:
                    token = kutils.refresh_access_token(session.get("refresh_token"))
                except Exception:
                    if session.get("REMEMBER_ME") and "USER_PASSWORD" in session:
                        # If refresh token is invalid, try to get a new access token using username and
                        # password since the has requested to remember him during login
                        token = kutils.get_token(
                            session.get("USER_EMAIL"), session.get("USER_PASSWORD")
                        )
                session["access_token"] = token["access_token"]
                session["refresh_token"] = token["refresh_token"]
                session["token_expires"] = current_time + token["expires_in"]
                session["refresh_expires"] = current_time + token["refresh_expires_in"]
                session["expires_in"] = token["expires_in"]
                session["refresh_expires_in"] = token["refresh_expires_in"]
                logger.debug("Token refreshed successfully")
                # Token refreshed, continue with the original request
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error refreshing token: {e}")

            try:
                kutils.KEYCLOAK_OPENID_CLIENT().logout(session.get("refresh_token"))
            except Exception as logout_e:
                logger.error(f"Error during logout: {logout_e}")

            session.clear()
            flash("Session Expired, Please Login Again", "warning")
            return redirect(url_for("dashboard_blueprint.login", next=request.url))

        if "2FA_FLOW_IN_PROGRESS" in session and session["2FA_FLOW_IN_PROGRESS"]:
            # Redirect to 2FA verification page
            return redirect(url_for("dashboard_blueprint.verify_2fa", next=request.url))

        # If token is valid, continue with the requested function
        return f(*args, **kwargs)

    return decorated_function


def handle_error(redirect_route="dashboard_index", **redirect_kwargs):
    """
    Custom decorator to handle errors in the dashboard routes.
    Redirects to the specified parent page on error.

    Args:
        redirect_route: The name of the route to redirect to on error
        **redirect_kwargs: Any keyword arguments to pass to url_for when redirecting
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)

            except AuthorizationError as e:
                logger.error(f"Authorization error: {e}")
                return render_stelar_template(
                    "403.html", PARTNER_IMAGE_SRC=get_partner_logo()
                )
            except Exception as e:
                logger.error(f"An error occurred: {str(e)}", "error")
                return redirect(
                    url_for(f"dashboard_blueprint.{redirect_route}", **redirect_kwargs)
                )

        return decorated_function

    return decorator


def evaluate_permissions(entity, resource_name, permissions):
    """
    permissions: dict mapping the key you want in the template
                 to the actual permission string you pass to authorize()
    """
    results = {}
    for key, perm in permissions.items():
        try:
            results[key] = authorize(entity, resource_name, perm)
        except AuthorizationError:
            results[key] = False

        # Default None to False, no permission granted
        if results[key] is None:
            results[key] = False

    return results


def require_permissions(
    *,
    entity_loader,  # callable: id -> entity
    id_arg,  # str: name of the view-kwarg
    resource_name,  # str: passed into authorize()
    permission_map,  # dict: flag_name -> permission string
):
    def decorator(view_fn):
        @wraps(view_fn)
        def wrapped(*args, **kwargs):
            # pull the ID out of kwargs
            entity_id = kwargs.get(id_arg)
            if entity_id is None:
                raise RuntimeError(
                    f"@require_permissions: '{id_arg}' not in view kwargs"
                )

            entity = entity_loader(entity_id)

            # Use the provided resource_name
            actual_resource_name = resource_name

            if actual_resource_name == "package":
                try:
                    actual_resource_name = PackageEntity.resolve_type(entity_id)
                except Exception:
                    logger.error(
                        f"Failed to resolve resource type for entity {entity_id}, defaulting to 'dataset'"
                    )
                    actual_resource_name = "dataset"

            # evaluate all perms
            perms = evaluate_permissions(entity, actual_resource_name, permission_map)

            # stash it on g (or pass it into the view)
            g.authorized_actions = perms

            # call the original view
            return view_fn(*args, **kwargs)

        return wrapped

    return decorator


# Home page (redirect target after login)
@dashboard_bp.route("/")
@session_required
def dashboard_index():
    return render_stelar_template("index.html", PARTNER_IMAGE_SRC=get_partner_logo())


# -------------------------------------
# LLM Search Route
# -------------------------------------
@dashboard_bp.route("/search", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
@llm_search_enabled
def llm_search():
    return render_stelar_template(
        "llm_search.html", PARTNER_IMAGE_SRC=get_partner_logo()
    )


# -------------------------------------
# Workflow Processes Routes
# -------------------------------------
@dashboard_bp.route("/processes")
@session_required
def processes():

    # Retrieve list of WFs from DB
    processes = PROCESS.search_entities(
        {
            "fl": ["metadata_created", "organization"],
            "limit": 1000,
        }
    )["results"]

    query = request.args.get("q")

    if processes is not None and processes != []:

        monthly_counts = {}
        organization_counts = {}  # Dictionary to count processes per organization
        for proc in processes:
            # Count processes per organization
            org_key = proc.get("organization", "Unknown")
            if org_key not in organization_counts:
                organization_counts[org_key] = {"title": org_key, "count": 0}

            organization_counts[org_key]["count"] += 1

            # Count process per month for bar chart
            start_date = datetime.strptime(
                proc["metadata_created"], "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            month_year = start_date.strftime("%Y-%m")
            monthly_counts[month_year] = monthly_counts.get(month_year, 0) + 1

        # Get the last three months + current month for bar chart display
        today = datetime.today()
        months_to_display = [
            (today - timedelta(days=30 * i)).strftime("%Y-%m") for i in range(3, -1, -1)
        ]

        # Ensure monthly_counts includes all three months (set to 0 if missing)
        monthly_counts = {
            month: monthly_counts.get(month, 0) for month in months_to_display
        }

        return render_stelar_template(
            "processes.html",
            processes=processes,
            monthly_counts=monthly_counts,
            organization_counts=organization_counts,
            search_query=query,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )

    else:
        return render_stelar_template(
            "processes.html",
            processes={},
            monthly_counts={},
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )


@dashboard_bp.route("/process/<process_id>")
@session_required
@handle_error(redirect_route="processes")
@require_permissions(
    entity_loader=PROCESS.get_entity,
    id_arg="process_id",
    resource_name="process",
    permission_map={"can_update": "update"},
)
def process(process_id):

    if not process_id:
        return redirect(url_for("dashboard_blueprint.dashboard_index"))

    process = PROCESS.get_entity(process_id)

    now = datetime.now()

    return render_stelar_template(
        "process.html",
        process=process,
        now=now,
        proc_tasks=(process.get("tasks") if process and "tasks" in process else []),
        PARTNER_IMAGE_SRC=get_partner_logo(),
        AUTHORIZED_ACTIONS=g.authorized_actions,
    )


@dashboard_bp.route("/tasks/compare")
@session_required
def task_compare():
    task_ids = request.cookies.get("compare_tasks", "").split(",")[:5]
    tasks = []
    resources = {}

    for tid in task_ids:
        try:
            t = TASK.get_entity(tid)
            for input_key, input_values in t.get("inputs", {}).items():
                for input_item in input_values:
                    if is_valid_uuid(input_item):
                        resource_id = input_item
                        if resource_id and resource_id not in resources:
                            try:
                                resources[resource_id] = RESOURCE.get_entity(
                                    resource_id
                                )
                            except Exception as e:
                                logger.error(
                                    f"Error fetching resource {resource_id}: {str(e)}"
                                )

            for output_key, output_value in t.get("outputs", {}).items():
                resource_id = output_value.get("resource_id")
                if is_valid_uuid(resource_id):
                    if resource_id and resource_id not in resources:
                        try:
                            resources[resource_id] = RESOURCE.get_entity(resource_id)
                        except Exception as e:
                            logger.error(
                                f"Error fetching resource {resource_id}: {str(e)}"
                            )

            tasks.append(t)
        except Exception as e:
            logger.error(f"Error fetching task {tid}: {str(e)}")

    now = datetime.now()

    return render_stelar_template(
        "task_compare.html", tasks=tasks, resources=resources, now=now
    )


@dashboard_bp.route("/task/<process_id>/<task_id>")
@handle_error(redirect_route="processes")
@session_required
def task(process_id, task_id):
    # Basic input validation
    if not process_id or not task_id:
        return redirect(url_for("dashboard_blueprint.login"))

    task_metadata = TASK.get_entity(task_id)
    task_metadata["process_title"] = PROCESS.get_entity(process_id)["title"]

    # Do not allow mismatch between given wf and actual wf
    if task_metadata.get("process_id") != process_id:
        return redirect(url_for("dashboard_blueprint.login"))

    input_metadata = TASK.get_input(
        id=task_id, include_input_ids=True, internal_call=True
    )

    logs_metadata = TASK.get_job_info(id=task_id)

    return render_stelar_template(
        "task.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        task=task_metadata,
        input=input_metadata,
        logs=logs_metadata,
    )


# -------------------------------------
# Catalog Routes
# -------------------------------------


@dashboard_bp.route("/catalog", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
def catalog():

    # -------------- Handle search query ---------------
    sort = request.args.get("sort")
    tags = request.args.get("tags")
    keyword = request.args.get("keywords")
    res_format = request.args.get("res_format")
    org = request.args.get("org")
    author = request.args.get("author")
    spatial = request.args.get("bbox")
    temporal_end = request.args.get("temporal_end")
    temporal_start = request.args.get("temporal_start")

    search_q = {}
    # Sort the results according to the user's latest option
    search_q["sort"] = sort if sort else "metadata_modified desc"

    # Search for datasets according to the user's search query
    search_q["tags"] = tags if tags else None
    search_q["keywords"] = keyword if keyword else None
    search_q["res_format"] = res_format if res_format else None
    search_q["organization"] = org if org else None
    search_q["author"] = author if author else None
    search_q["bbox"] = [float(num) for num in spatial.split(",")] if spatial else None
    search_q["temporal_end"] = (
        datetime.strptime(temporal_end, "%Y-%m-%d") if temporal_end else None
    )
    search_q["temporal_start"] = (
        datetime.strptime(temporal_start, "%Y-%m-%d") if temporal_start else None
    )

    fq_filters = []
    # For fields except spatial, temporal_start, and temporal_end
    for field in ["tags", "res_format", "organization", "author"]:
        value = search_q.get(field)
        if value:
            values = (
                [v.strip() for v in value.split(",")]
                if "," in value
                else [value.strip()]
            )
            # Add a space after colon for "tags" to match frontend expectations if needed
            if field == "tags":
                fq_filters.append(f"{field}: (" + " OR ".join(values) + ")")
            else:
                fq_filters.append(f"{field}:(" + " OR ".join(values) + ")")

    search_q["fq"] = fq_filters

    return render_stelar_template(
        "catalog.html",
        search_q=search_q,
        tags=TAG.list_entities(limit=200, offset=0),
        PARTNER_IMAGE_SRC=get_partner_logo(),
    )


@dashboard_bp.route("/catalog/<dataset_id>", methods=["GET", "POST"])
@session_required
@handle_error(redirect_route="catalog")
@require_permissions(
    entity_loader=cutils.get_package,
    id_arg="dataset_id",
    resource_name="package",
    permission_map={
        "can_update": "update",
        "can_delete": "delete",
        "can_edit_ownership": "edit_ownership",
    },
)
def dataset_detail(dataset_id):
    metadata_data = None
    try:
        metadata_data = cutils.get_package(id=dataset_id)
    except Exception:
        return redirect(url_for("dashboard_blueprint.catalog"))

    # Tool packages should redirect to the tool view
    if metadata_data.get("type") == "tool":
        return redirect(url_for("dashboard_blueprint.tool", tool_id=dataset_id))

    if metadata_data:
        return render_stelar_template(
            "catalog_view.html",
            dataset=metadata_data,
            PARTNER_IMAGE_SRC=get_partner_logo(),
            AUTHORIZED_ACTIONS=g.authorized_actions,
        )
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/<dataset_id>/annotate")
@handle_error(redirect_route="catalog")
@session_required
def dataset_annotate(dataset_id):

    metadata_data = None
    metadata_data = cutils.get_package(id=dataset_id)

    if metadata_data:
        return render_stelar_template(
            "annotator.html",
            dataset=metadata_data,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/<dataset_id>/relationships")
@handle_error(redirect_route="catalog")
@session_required
def dataset_relationships(dataset_id):

    metadata_data = cutils.get_package(id=dataset_id)

    if metadata_data:
        return render_stelar_template(
            "relationships.html",
            package=metadata_data,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/resource/<resource_id>")
@session_required
@handle_error(redirect_route="catalog")
def viewResource(resource_id):
    config = current_app.config["settings"]
    host = config.get("MAIN_EXT_URL")

    if resource_id:

        minio_console_url = config.get("S3_CONSOLE_URL").replace("login", "browser/")
        resource = RESOURCE.get_entity(resource_id)
        try:
            package = DATASET.get_entity(resource.get("package_id"))
        except Exception:
            try:
                package = PROCESS.get_entity(resource.get("package_id"))
            except Exception:
                package = None

        s3_link = None

        url = resource.get("url")
        if url and url.startswith("s3://"):
            s3_link = url.replace("s3://", minio_console_url)

        s3_endpoint = (
            config.get("MINIO_API_SUBDOMAIN") + "." + config.get("KLMS_DOMAIN_NAME")
        )
        creds = mutils.get_temp_minio_credentials(kutils.current_token())

        embed_uri = (
            f"/previewer/?embed=true"
            f"&access_key={quote(creds['AccessKeyId'])}"
            f"&secret_key={quote(creds['SecretAccessKey'])}"
            f"&session_token={quote(creds['SessionToken'])}"
            f"&s3_endpoint={quote(s3_endpoint)}"
            f"&s3_path={quote(resource.get('url'))}"
        )
        return render_stelar_template(
            "resource.html",
            S3_LINK=s3_link,
            GUI_URL=host + embed_uri,
            PARTNER_IMAGE_SRC=get_partner_logo(),
            resource=resource,
            package=package,
        )
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/visualize/<profile_id>")
@handle_error(redirect_route="catalog")
@session_required
def visualize(profile_id):
    config = current_app.config["settings"]
    host = config.get("MAIN_EXT_URL")

    # Get the profile path from the Catalog
    resource = RESOURCE.get_entity(profile_id)
    if resource.get("relation") != "profile":
        return redirect(url_for("dashboard_blueprint.catalog"))

    package_name = DATASET.get_entity(resource.get("package_id"))["title"]

    profile_file = resource.get("url")

    s3_endpoint = (
        config.get("MINIO_API_SUBDOMAIN") + "." + config.get("KLMS_DOMAIN_NAME")
    )
    creds = mutils.get_temp_minio_credentials(kutils.current_token())

    embed_uri = (
        f"/visualizer/?embed=true"
        f"&access_key={quote(creds['AccessKeyId'])}"
        f"&secret_key={quote(creds['SecretAccessKey'])}"
        f"&session_token={quote(creds['SessionToken'])}"
        f"&s3_endpoint={quote(s3_endpoint)}"
        f"&s3_path={quote(profile_file)}"
    )

    return render_stelar_template(
        "visualizer.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        VIS_URL=host + embed_uri,
        profile=resource,
        package_name=package_name,
    )


@dashboard_bp.route("/datasets/compare", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
def dataset_compare():
    dataset_ids = request.cookies.get("compare_datasets", "").split(",")[:5]
    datasets = []

    for dataset_id in dataset_ids:
        try:
            dataset = cutils.get_package(id=dataset_id)
            if dataset:
                datasets.append(dataset)
        except Exception as e:
            logging.error(f"Error fetching dataset {dataset_id}: {str(e)}")

    return render_stelar_template(
        "dataset_compare.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        datasets=datasets,
    )


# --------------------------------------
# Utilities Routes
# --------------------------------------
@dashboard_bp.route("/utilities/sde", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
def sde_manager():

    config = current_app.config["settings"]
    host = config.get("MAIN_EXT_URL")

    s3_endpoint = (
        config.get("MINIO_API_SUBDOMAIN") + "." + config.get("KLMS_DOMAIN_NAME")
    )
    creds = mutils.get_temp_minio_credentials(kutils.current_token())

    embed_uri = (
        f"/sde/?embed=true"
        f"&api={quote(host + '/stelar')}"
        f"&username={quote(session.get('USER_USERNAME', ''))}"
        f"&access_token={quote(session.get('access_token', ''))}"
        f"&refresh_token={quote(session.get('refresh_token', ''))}"
        f"&expires_in={int(session.get('expires_in', 0))}"
        f"&refresh_expires_in={int(session.get('refresh_expires_in', 0))}"
        f"&access_key={quote(creds['AccessKeyId'])}"
        f"&secret_key={quote(creds['SecretAccessKey'])}"
        f"&session_token={quote(creds['SessionToken'])}"
        f"&s3_endpoint={quote(s3_endpoint)}"
        f"&bucket=klms-bucket"
    )
    return render_stelar_template(
        "sde.html",
        GUI_URL=host + embed_uri,
        PARTNER_IMAGE_SRC=get_partner_logo(),
    )


# --------------------------------------
# Tools Routes
# --------------------------------------


@dashboard_bp.route("/tools", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
def tools():
    registry = current_app.config["settings"].get("REGISTRY_EXT_URL")
    if registry:
        registry = re.sub(r"^https?://", "", registry)

    return render_stelar_template(
        "tools.html", REGISTRY_URL=registry, PARTNER_IMAGE_SRC=get_partner_logo()
    )


@dashboard_bp.route("/tool/<tool_id>", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
@handle_error(redirect_route="tools")
@require_permissions(
    entity_loader=TOOL.get_entity,
    id_arg="tool_id",
    resource_name="tool",
    permission_map={"can_update": "update", "can_delete": "delete"},
)
def tool(tool_id):

    tool = TOOL.get_entity(tool_id)

    if (
        "git_repository" in tool
        and tool["git_repository"] is not None
        and tool["git_repository"] != ""
    ):
        # Extract the GitHub repository information
        repo_info = extract_github_repo_info(tool["git_repository"])
        if repo_info:
            tool["git_user"], tool["git_repo"] = repo_info

    if "repository" in tool and tool["repository"] is not None:
        registry = current_app.config["settings"].get("REGISTRY_EXT_URL")
        if registry:
            registry = re.sub(r"^https?://", "", registry)
            image_repo = registry + "/stelar/" + tool["repository"]
            logger.debug("Image repo: %s", image_repo)
            tool["repository"] = image_repo

    return render_stelar_template(
        "tool.html",
        tool=tool,
        PARTNER_IMAGE_SRC=get_partner_logo(),
        AUTHORIZED_ACTIONS=g.authorized_actions,
    )


# --------------------------------------
# Organizations & Groups Routes
# --------------------------------------


@dashboard_bp.route("/organizations")
@session_required
def organizations():
    return render_stelar_template(
        "organizations.html", PARTNER_IMAGE_SRC=get_partner_logo()
    )


@dashboard_bp.route("/organization/<organization_id>")
@session_required
@require_permissions(
    entity_loader=ORGANIZATION.get_entity,
    id_arg="organization_id",
    resource_name="organization",
    permission_map={
        "add_member": "add_member",
        "remove_member": "remove_member",
        "can_update": "update",
    },
)
def organization(organization_id):
    org = ORGANIZATION.get_entity(organization_id)

    return render_stelar_template(
        "organization.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        organization=org,
        AUTHORIZED_ACTIONS=g.authorized_actions,
    )


# -------------------------------------------
# Admin Settings & Account Settings Routes
# -------------------------------------------


@dashboard_bp.route("/admin-settings")
@session_required
@admin_required
def adminSettings():
    return render_stelar_template("cluster.html", PARTNER_IMAGE_SRC=get_partner_logo())


# Settings Route
@dashboard_bp.route("/settings")
@session_required
def settings():
    TWO_FACTOR_AUTH = dict()
    try:
        # Fetch user's 2FA status
        TWO_FACTOR_AUTH = kutils.stat_user_2fa(session.get("KEYCLOAK_ID_USER"))
        created_at = TWO_FACTOR_AUTH.get("created_at")
        if created_at:
            TWO_FACTOR_AUTH["created_at"] = created_at.strftime("%d-%m-%Y %H:%M:%S")
    except Exception:
        pass
    return render_stelar_template(
        "settings.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        REGISTRY_EXT_URL=current_app.config["settings"].get("REGISTRY_EXT_URL"),
        TWO_FACTOR_AUTH=TWO_FACTOR_AUTH,
    )


# --------------------------------------
# 2FA & Reset Routes
# --------------------------------------
@dashboard_bp.route("/login/verify", methods=["GET", "POST"])
def verify_2fa(next_url=None):
    if request.method == "GET":
        if "ACTIVE" in session and session["ACTIVE"]:
            return redirect(url_for("dashboard_blueprint.dashboard_index"))
        else:
            return render_template("2fa.html", PARTNER_IMAGE_SRC=get_partner_logo())
    elif request.method == "POST":
        token = request.form.get("token")
        if request.form.get("cancel"):
            session.pop("PASSWORD_RESET_FLOW", None)
            session.clear()
            return redirect(url_for("dashboard_blueprint.login"))

        if token:
            try:
                kutils.validate_2fa_otp(session.get("KEYCLOAK_ID_USER"), token)
                session["ACTIVE"] = True
                session.pop("2FA_FLOW_IN_PROGRESS", None)
                if next_url:
                    return redirect(next_url)
                else:
                    return redirect(url_for("dashboard_blueprint.dashboard_index"))
            except ValueError:
                flash("OTP is not valid", "danger")
                return render_template("2fa.html", PARTNER_IMAGE_SRC=get_partner_logo())
            except Exception as e:
                flash("An error occurred", "danger")
                return render_template("2fa.html", PARTNER_IMAGE_SRC=get_partner_logo())
        else:
            flash("Please provide a valid OTP", "warning")
            return render_template("2fa.html", PARTNER_IMAGE_SRC=get_partner_logo())


@dashboard_bp.route("/login/forgot", methods=["GET", "POST"])
def forgot_password(next_url=None):
    if request.method == "GET":
        if "ACTIVE" in session and session["ACTIVE"]:
            return redirect(url_for("dashboard_blueprint.dashboard_index"))
        else:
            return render_template("forgot.html")
    elif request.method == "POST":
        account = request.form.get("account")
        if account:
            try:
                kutils.reset_password_init_flow(email=account)
                session["PASSWORD_RESET_FLOW"] = True
                return redirect(
                    url_for("dashboard_blueprint.forgot_password_sent_email")
                )
            except Exception as e:
                pass
        return render_template("forgot.html")


@dashboard_bp.route("/login/forgot/next")
def forgot_password_sent_email():
    if request.method == "GET":
        if "ACTIVE" in session and session["ACTIVE"]:
            return redirect(url_for("dashboard_blueprint.dashboard_index"))
        if "PASSWORD_RESET_FLOW" in session and session["PASSWORD_RESET_FLOW"]:
            return render_template("reset_email_sent.html")
        else:
            return redirect(url_for("dashboard_blueprint.login"))


@dashboard_bp.route("/login/reset/<rs_token>", methods=["GET", "POST"])
def reset_password(rs_token):
    if "ACTIVE" in session and session["ACTIVE"]:
        return redirect(url_for("dashboard_blueprint.dashboard_index"))

    if "PASSWORD_RESET_FLOW" not in session or not session["PASSWORD_RESET_FLOW"]:
        # If the reset flow is not active, redirect to login
        return redirect(url_for("dashboard_blueprint.login"))

    try:
        payload = kutils.verify_reset_token(rs_token)
    except Exception:
        # If token is invalid or expired, redirect to login
        session["PASSWORD_RESET_FLOW"] = False
        return redirect(url_for("dashboard_blueprint.login"))

    if request.method == "GET" and rs_token:

        return render_template("new_password.html")

    elif request.method == "POST" and payload:
        new_password = request.form.get("passwordIn")
        confirm_password = request.form.get("passwordRepeatIn")
        if not new_password or not confirm_password:
            return render_template(
                "new_password.html", STATUS="ERROR", ERROR_MSG="Passwords do not match!"
            )

        if new_password != confirm_password:
            return render_template(
                "signup.html", STATUS="ERROR", ERROR_MSG="Passwords do not match."
            )

        if not re.match(r"^(?=.*[A-Z])(?=.*\d)(?=.*[^\w]).{8,}$", confirm_password):
            return render_template(
                "new_password.html",
                STATUS="ERROR",
                ERROR_MSG="Password does not meet minimum requirements.",
            )

        try:
            if kutils.reset_user_password(
                user_id=payload["user_id"], new_password=new_password
            ):
                session["PASSWORD_RESET_FLOW"] = False
                return redirect(url_for("dashboard_blueprint.login"))
            else:
                flash("Password reset failed. Please try again.", "danger")
                return render_template("new_password.html")
        except Exception as e:
            session["PASSWORD_RESET_FLOW"] = False
            return redirect(url_for("dashboard_blueprint.login"))


# ----------------------------------------
# Walkthrough Routes
# ----------------------------------------
@dashboard_bp.route("/walkthroughs", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
def walkthroughs():
    """
    Renders the walkthroughs page with available walkthroughs.
    """

    # Iterate the walkthroughs directory to find all walkthroughs
    # registered in the system.
    walkthroughs = []

    walkthroughs_dir = os.path.join(current_app.root_path, "templates", "walkthroughs")
    if os.path.exists(walkthroughs_dir):
        for filename in os.listdir(walkthroughs_dir):
            # The subdirs are the walkthroughs
            if os.path.isdir(os.path.join(walkthroughs_dir, filename)):
                # Check if the walkthrough has a spec.json file
                # defining the walkthrough
                spec_path = os.path.join(walkthroughs_dir, filename, "spec.json")
                if os.path.exists(spec_path):
                    try:
                        with open(spec_path, "r") as spec_file:
                            spec = json.load(spec_file)
                            walkthroughs.append(
                                {
                                    "name": filename,
                                    "title": spec.get("title", filename),
                                    "description": spec.get("description", ""),
                                    "time": spec.get("time", 0),
                                    "pilot": spec.get("pilot", ""),
                                    "usecase": spec.get("usecase", ""),
                                    "tags": spec.get("tags", []),
                                    "image": url_for(
                                        "static",
                                        filename=f'walkthroughs/{spec.get("image", "")}',
                                    ),
                                    "walkthrough": spec.get("walkthrough", ""),
                                }
                            )
                    except Exception as e:
                        logger.error(f"Error loading spec for {filename}: {e}")

    return render_stelar_template(
        "walkthroughs.html",
        walkthroughs=walkthroughs,
        PARTNER_IMAGE_SRC=get_partner_logo(),
    )


@dashboard_bp.route("/walkthroughs/<walkthrough_name>", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
def walkthrough(walkthrough_name):
    """
    Renders a specific walkthrough page.
    """
    walkthroughs_dir = os.path.join(current_app.root_path, "templates", "walkthroughs")
    walkthrough_path = os.path.join(walkthroughs_dir, walkthrough_name)

    if not os.path.exists(walkthrough_path):
        return redirect(url_for("dashboard_blueprint.walkthroughs"))

    spec_path = os.path.join(walkthrough_path, "spec.json")
    if not os.path.exists(spec_path):
        return redirect(url_for("dashboard_blueprint.walkthroughs"))

    try:
        with open(spec_path, "r") as spec_file:
            spec = json.load(spec_file)

            if spec.get("walkthrough"):
                # If the spec has a readme, render it as markdown
                readme_path = os.path.join(walkthrough_path, spec["walkthrough"])
                if os.path.exists(readme_path):
                    with open(readme_path, "r") as readme_file:
                        spec["readme_content"] = readme_file.read()
                else:
                    spec["readme_content"] = None

                raw = (
                    spec.get("readme_content").encode("utf-8").decode("unicode_escape")
                )
                spec["readme"] = markdown.markdown(raw, extensions=["fenced_code"])

            else:
                spec["readme"] = "No walkthrough content available."

            # Validate required fields in the spec
            required_fields = [
                "title",
                "description",
                "time",
                "pilot",
                "usecase",
                "tags",
                "readme",
            ]

            if not all(field in spec for field in required_fields):
                logger.error(
                    f"Walkthrough {walkthrough_name} is missing required fields: {required_fields}"
                )
                return redirect(url_for("dashboard_blueprint.walkthroughs"))

            return render_stelar_template(
                "walkthrough.html",
                walkthrough=spec,
                PARTNER_IMAGE_SRC=get_partner_logo(),
            )
    except Exception as e:
        logger.error(f"Error loading spec for {walkthrough_name}: {e}")
        return redirect(url_for("dashboard_blueprint.walkthroughs"))


# ----------------------------------------
# Signup Routes
# ----------------------------------------
@dashboard_bp.route("/signup", methods=["GET", "POST"])
def signup():
    # Handle signup POST request (form submitted).
    if request.method == "POST":
        fullname = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("passwordIn")
        passwordRepeat = request.form.get("passwordRepeatIn")

        if not fullname or len(fullname.split()) < 2:
            return render_template(
                "signup.html", STATUS="ERROR", ERROR_MSG="Please provide a valid name."
            )
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            return render_template(
                "signup.html", STATUS="ERROR", ERROR_MSG="Invalid email address."
            )
        if password != passwordRepeat:
            return render_template(
                "signup.html", STATUS="ERROR", ERROR_MSG="Passwords do not match."
            )
        if not re.match(r"^(?=.*[A-Z])(?=.*\d)(?=.*[^\w]).{8,}$", password):
            return render_template(
                "signup.html",
                STATUS="ERROR",
                ERROR_MSG="Password does not meet minimum requirements.",
            )

        try:
            kutils.email_unique(email=email)
        except ValueError:
            return render_template(
                "signup.html", STATUS="ERROR", ERROR_MSG="Mail address already in use"
            )

        # We need to decide the user's new username based on what usernames are already present in the system.
        username_base = re.sub(r"[\s\-\_\.]", "", email.split("@")[0])
        username = username_base
        counter = 0
        while True:
            # Should not reach this, just for safety.
            if counter == 20:
                break
            try:
                # Check if the username is unique.
                kutils.username_unique(username)
                break
            except ConflictError:
                # If not unique, append a counter to the base username.
                counter += 1
                username = f"{username_base}{counter}"
        try:
            new_uid = kutils.create_user_with_password(
                username=username,
                email=email,
                first_name=fullname.split()[0],
                last_name=fullname.split()[1],
                password=password,
                enabled=False,
                email_verified=False,
            )
            if new_uid:
                # Generate the vftoken for the email verification.
                plain = f"{username}{email}"
                vftoken = hashlib.sha256(plain.encode("utf-8")).hexdigest()
                # Send verification email
                send_verification_email(
                    email, vftoken=vftoken, id=new_uid["id"], fullname=fullname
                )
                # Registration was succesful
                return render_template("signup.html", STATUS="SUCCESS")
            else:
                return render_template(
                    "signup.html",
                    STATUS="ERROR",
                    ERROR_MSG="Registration could not be completed. KC Error 0x001",
                )
        except Exception as e:
            return render_template(
                "signup.html",
                STATUS="ERROR",
                ERROR_MSG=f"Registration could not be completed ML Error 0x001 {str(e)}",
            )
    else:
        return render_template("signup.html")


# Email verification status
@dashboard_bp.route("/verify")
def verify_email():
    if request.method == "GET":
        if request.args.get("vftoken") and request.args.get("id"):
            uid = request.args.get("id")
            vftoken = request.args.get("vftoken")
            # Token and email were given, proceed with the verification
            try:
                # Fetch user from keycloak to check the status of email verification
                user = kutils.get_user(uid)
                if not user.get("emailVerified"):
                    email = user.get("email")
                    username = user.get("username")

                    # Reproduce the hash to
                    plain = f"{username}{email}"
                    cipher = hashlib.sha256(plain.encode("utf-8")).hexdigest()

                    # Cool the token given and the hash match, the email of the user becomes verified
                    if cipher == vftoken:
                        # We update the status of the email verification by updating the user in keycloak
                        kutils.update_user(user_id=uid, email_verified=True)
                        return render_template("verify.html", VERIFY_STATUS=True)
                    else:
                        # Sadly the email wasn't verified
                        return render_template("verify.html", VERIFY_STATUS=False)

                else:
                    # If user's email is already verified do nothing
                    return redirect(url_for("dashboard_blueprint.login"))
            except:
                # Didnt no what to do?!
                return redirect(url_for("dashboard_blueprint.login"))

    return redirect(url_for("dashboard_blueprint.login"))


# ---------------------------------------
# Login Route
# ---------------------------------------


@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles the Authentication process of a user given his credentials.
    Talks with the specified Keycloak instance to authenticate the user and fetch
    his info (roles, name, username, etc). Inits an active session.
    """
    EMPTY_EMAIL_ERROR = False
    EMPTY_PASSWORD_ERROR = False
    LOGIN_ERROR = False
    INACTIVE_ERROR = False

    # Check if the user is already logged in and redirect him to console home page if so
    if request.method == "GET":

        if "2FA_FLOW_IN_PROGRESS" in session and session["2FA_FLOW_IN_PROGRESS"]:
            return redirect(url_for("dashboard_blueprint.verify_2fa"))
        if "ACTIVE" in session and session["ACTIVE"]:
            return redirect(url_for("dashboard_blueprint.dashboard_index"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        remember = (
            request.form.get("remember") == "on"
            if "remember" in request.form
            else False
        )

        # Basic validation
        if not email:
            EMPTY_EMAIL_ERROR = True
        if not password:
            EMPTY_PASSWORD_ERROR = True

        # If no validation errors, proceed with login
        if not EMPTY_EMAIL_ERROR and not EMPTY_PASSWORD_ERROR:
            try:
                # Request a token from Keycloak
                token = kutils.get_token(email, password)
                session["access_token"] = token["access_token"]
                session["refresh_token"] = token["refresh_token"]
                session["token_expires"] = int(time.time()) + token["expires_in"]
                session["refresh_expires"] = (
                    int(time.time()) + token["refresh_expires_in"]
                )

                # Store the original expiration dates
                session["expires_in"] = token["expires_in"]
                session["refresh_expires_in"] = token["refresh_expires_in"]

                # Introspect the token to get user details
                userinfo = kutils.get_user_by_token(token["access_token"])

                if userinfo:
                    session["USER_NAME"] = userinfo.get("name")
                    session["USER_EMAIL"] = userinfo.get("email")
                    session["USER_EMAIL_VERIFIED"] = userinfo.get(
                        "email_verified", False
                    )
                    session["USER_USERNAME"] = userinfo.get("preferred_username")

                    if remember:
                        session["USER_PASSWORD"] = password
                    session["REMEMBER_ME"] = remember
                    session["AVATAR"] = get_avatar()
                    session["USER_ROLES"] = userinfo.get("realm_access", {}).get(
                        "roles", []
                    )
                    session["KEYCLOAK_ID_USER"] = userinfo.get("sub")

                    # Fetch user creation date using client credentials
                    creation_date = kutils.fetch_user_creation_date(
                        session["KEYCLOAK_ID_USER"]
                    )
                    if creation_date:
                        session["USER_CREATION_DATE"] = creation_date

                    # After login, redirect to the original page (if provided)
                    next_url = request.args.get("next")

                    if kutils.user_has_2fa(session["KEYCLOAK_ID_USER"]):
                        session["2FA_FLOW_IN_PROGRESS"] = True
                        return redirect(url_for("dashboard_blueprint.verify_2fa"))

                    session["ACTIVE"] = True
                    if next_url:
                        return redirect(next_url)
                    else:
                        return redirect(url_for("dashboard_blueprint.dashboard_index"))
                else:
                    LOGIN_ERROR = True
            except Exception as e:
                logger.debug(f"Error during login: {e}")
                # Handle exceptions during the token request
                if "disabled" in str(e):
                    INACTIVE_ERROR = True
                else:
                    LOGIN_ERROR = True

    # Pass error flags to the template. This is the login page frontend
    return render_template(
        "login.html",
        EMPTY_EMAIL_ERROR=EMPTY_EMAIL_ERROR,
        EMPTY_PASSWORD_ERROR=EMPTY_PASSWORD_ERROR,
        LOGIN_ERROR=LOGIN_ERROR,
        INACTIVE_ERROR=INACTIVE_ERROR,
        PARTNER_IMAGE_SRC=get_partner_logo(),
    )


# ---------------------------------------
# Logout Route
# ---------------------------------------
@dashboard_bp.route("/logout")
def logout():
    if "ACTIVE" not in session or not session["ACTIVE"]:
        return redirect(url_for("dashboard_blueprint.login"))

    # Revoke refresh token to log out
    try:
        kutils.KEYCLOAK_OPENID_CLIENT().logout(session["refresh_token"])
    except Exception as e:
        print(f"Error during logout: {e}")

    # Clear local session and redirect to the login page
    session.clear()
    return redirect(url_for("dashboard_blueprint.login"))


##################################
# this should be moved to another location....
##################################


def send_verification_email(to_email, vftoken, id, fullname):
    """
    Sends the email verification to the specified email address with a subject and sender name.
    SMTP settings are fetched from Flask's app config.
    """
    config = current_app.config["settings"]  # Fetch SMTP settings from app config

    smtp_server = config["SMTP_SERVER"]
    smtp_port = config["SMTP_PORT"]
    sender_email = config["SMTP_EMAIL"]
    sender_password = config["SMTP_PASSWORD"]

    # Email subject and sender name
    subject = "Verify Your Email Address"
    sender_name = "STELAR KLMS"

    # Plain text message without headers (headers will be handled separately)
    plain_message = f"""\
Dear {fullname},

Follow this link to verify your email: 

{config['MAIN_EXT_URL']}{url_for('dashboard_blueprint.verify_email')}?id={id}&vftoken={vftoken}

If you received this email by accident, please ignore it.

Kind Regards,
STELAR KLMS
"""
    # Create the full email message with subject, sender, and receiver
    full_message = f"Subject: {subject}\nFrom: {sender_name} <{sender_email}>\nTo: {to_email}\n\n{plain_message}"

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(smtp_server, int(smtp_port), context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, full_message)
    except Exception as e:
        # Log the error
        raise Exception(f"Error sending verification email: {str(e)}")
