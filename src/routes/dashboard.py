import hashlib
import logging

# FOR TESTING ONLY!!!
import os
import re
import smtplib
import ssl
from datetime import datetime, timedelta
from functools import wraps
from math import ceil
import execution
from urllib.parse import quote

import mutils

from apiflask import APIBlueprint

from exceptions import ConflictError
from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import cutils
import kutils
from processes import PROCESS
from tasks import TASK
from tools import TOOL
from cutils import TAG, ORGANIZATION, DATASET, RESOURCE
from auth import admin_required
import re

dashboard_bp = APIBlueprint("dashboard_blueprint", __name__, enable_openapi=False)

logger = logging.getLogger(__name__)


def render_template_with_s3(template_name, **kwargs):
    """
    Helper function to include the S3_CONSOLE_URL in all templates.
    """
    config = current_app.config["settings"]
    # Add the S3_CONSOLE_URL to the kwargs
    kwargs["S3_CONSOLE_URL"] = config.get("S3_CONSOLE_URL", "#")
    kwargs["AVATAR"] = session.get("AVATAR", None)
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

        # If token doesn't exist or is invalid, clear session and redirect to login with a message
        if not access_token or not kutils.is_token_active(access_token):
            # Revoke refresh token to log out
            try:
                kutils.KEYCLOAK_OPENID_CLIENT().logout(session["refresh_token"])
            except Exception as e:
                logger.error(f"Error during logout: {e}")
            session.clear()
            flash("Session Expired, Please Login Again", "warning")
            return redirect(url_for("dashboard_blueprint.login", next=request.url))

        if "2FA_FLOW_IN_PROGRESS" in session and session["2FA_FLOW_IN_PROGRESS"]:
            # Redirect to 2FA verification page
            return redirect(url_for("dashboard_blueprint.verify_2fa", next=request.url))

        # If token is valid, continue with the requested function
        return f(*args, **kwargs)

    return decorated_function


def handle_error(redirect="dashboard_index"):
    """
    Custom decorator to handle errors in the dashboard routes.
    Redirects to the specified parent page on error.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in route: {e}")
                return redirect(url_for(f"dashboard_blueprint.{redirect}"))

        return decorated_function

    return decorator


# Home page (redirect target after login)
@dashboard_bp.route("/")
@session_required
def dashboard_index():
    return render_template_with_s3("index.html", PARTNER_IMAGE_SRC=get_partner_logo())


# -------------------------------------
# Workflow Processes Routes
# -------------------------------------


@dashboard_bp.route("/processes")
@session_required
def processes():

    # Retrieve list of WFs from DB
    processes = PROCESS.fetch_entities(limit=50, offset=0)
    logger.debug(processes)

    if processes is not None and processes != []:
        status_counts = {}
        monthly_counts = {}

        for proc in processes:
            # Count process status for pie chart
            status = proc["exec_state"]
            status_counts[status] = status_counts.get(status, 0) + 1

            # Count process per month for bar chart
            start_date = proc["start_date"]
            month_year = start_date.strftime("%Y-%m")
            monthly_counts[month_year] = monthly_counts.get(month_year, 0) + 1

        # Get the last two months + current month for bar chart display
        today = datetime.today()
        months_to_display = [
            (today - timedelta(days=30 * i)).strftime("%Y-%m") for i in range(2, -1, -1)
        ]

        # Ensure monthly_counts includes all three months (set to 0 if missing)
        monthly_counts = {
            month: monthly_counts.get(month, 0) for month in months_to_display
        }

        return render_template_with_s3(
            "processes.html",
            processes=processes,
            status_counts=status_counts,
            monthly_counts=monthly_counts,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )

    else:
        return render_template_with_s3(
            "processes.html",
            processes={},
            status_counts={},
            monthly_counts={},
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )


@dashboard_bp.route("/process/<process_id>")
@session_required
def process(process_id):

    if not process_id:
        return redirect(url_for("dashboard_blueprint.dashboard_index"))

    process = PROCESS.get_entity(process_id)

    return render_template_with_s3(
        "process.html",
        process=process,
        proc_tasks=(process.get("tasks") if process and "tasks" in process else []),
        PARTNER_IMAGE_SRC=get_partner_logo(),
    )


@dashboard_bp.route("/task/<process_id>/<task_id>")
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

    input_metadata = TASK.get_input(id=task_id, include_input_ids=True)

    logs_metadata = TASK.get_job_info(id=task_id)

    return render_template_with_s3(
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
    search_q = {}
    # Sort the results according to the user's latest option
    search_q["sort"] = sort if sort else "metadata_modified desc"

    # Handle default GET request
    return render_template_with_s3(
        "catalog.html",
        search_q=search_q,
        tags=TAG.list_entities(limit=200, offset=0),
        PARTNER_IMAGE_SRC=get_partner_logo(),
    )


@dashboard_bp.route("/catalog/<dataset_id>", methods=["GET", "POST"])
@session_required
def dataset_detail(dataset_id):
    if request.method == "POST":
        if request.form.get("dataset_delete"):
            try:
                id = request.form.get("dataset_delete")
                if id == dataset_id:
                    cutils.delete_package(id)
                    return redirect(url_for("dashboard_blueprint.catalog"))
            except:
                return redirect(url_for("dashboard_blueprint.catalog"))
        else:
            return redirect(url_for("dashboard_blueprint.catalog"))
    else:
        metadata_data = None
        try:
            metadata_data = cutils.get_package(id=dataset_id)
        except ValueError as e:
            return redirect(url_for("dashboard_blueprint.catalog"))
        except Exception as e:
            return redirect(url_for("dashboard_blueprint.catalog"))

        if metadata_data:
            return render_template_with_s3(
                "catalog_view.html",
                dataset=metadata_data,
                PARTNER_IMAGE_SRC=get_partner_logo(),
            )
        else:
            return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/<dataset_id>/annotate")
@session_required
def dataset_annotate(dataset_id):

    metadata_data = None
    try:
        metadata_data = cutils.get_package(id=dataset_id)
    except ValueError as e:
        return redirect(url_for("dashboard_blueprint.catalog"))
    except Exception as e:
        return redirect(url_for("dashboard_blueprint.catalog"))

    if metadata_data:
        return render_template_with_s3(
            "annotator.html",
            dataset=metadata_data,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/<dataset_id>/relationships")
@session_required
def dataset_relationships(dataset_id):

    metadata_data = None
    try:
        metadata_data = cutils.get_package(id=dataset_id)
    except ValueError as e:
        return redirect(url_for("dashboard_blueprint.catalog"))
    except Exception as e:
        return redirect(url_for("dashboard_blueprint.catalog"))

    if metadata_data:
        return render_template_with_s3(
            "relationships.html",
            package=metadata_data,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/resource/<resource_id>")
@session_required
def viewResource(resource_id):
    config = current_app.config["settings"]
    if resource_id:
        try:
            minio_console_url = config.get("S3_CONSOLE_URL").replace(
                "login", "browser/"
            )
            resource_mtd = cutils.get_resource(id=resource_id)
            url = resource_mtd.get("url")
            if url and url.startswith("s3://"):
                url = url.replace("s3://", minio_console_url)
                resource_mtd["url"] = url
            return render_template_with_s3(
                "resource.html",
                PARTNER_IMAGE_SRC=get_partner_logo(),
                resource=resource_mtd,
            )
        except:
            return redirect(url_for("dashboard_blueprint.catalog"))
    else:
        return redirect(url_for("dashboard_blueprint.catalog"))


@dashboard_bp.route("/catalog/visualize/<profile_id>")
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

    s3_endpoint = "minio.stelar.gr"
    creds = mutils.get_temp_minio_credentials(kutils.current_token())

    embed_uri = (
        f"/visualizer/?embed=true"
        f"&access_key={quote(creds['AccessKeyId'])}"
        f"&secret_key={quote(creds['SecretAccessKey'])}"
        f"&session_token={quote(creds['SessionToken'])}"
        f"&s3_endpoint={quote(s3_endpoint)}"
        f"&s3_path={quote(profile_file)}"
    )

    return render_template_with_s3(
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

    logger.debug("Dataset IDs from the cookie: %d", dataset_ids)
    for dataset_id in dataset_ids:
        try:
            dataset = cutils.get_package(id=dataset_id)
            if dataset:
                datasets.append(dataset)
        except Exception as e:
            logging.error(f"Error fetching dataset {dataset_id}: {str(e)}")

    return render_template_with_s3(
        "dataset_compare.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        datasets=datasets,
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

    return render_template_with_s3(
        "tools.html", REGISTRY_URL=registry, PARTNER_IMAGE_SRC=get_partner_logo()
    )


@dashboard_bp.route("/tool/<tool_id>", methods=["GET"])
@dashboard_bp.doc(False)
@session_required
@handle_error(redirect="tools")
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

    if "repository" in tool:
        registry = current_app.config["settings"].get("REGISTRY_EXT_URL")
        if registry:
            registry = re.sub(r"^https?://", "", registry)
            image_repo = registry + "/stelar/" + tool["repository"]
            logger.debug("Image repo: %s", image_repo)
            tool["repository"] = image_repo

    return render_template_with_s3(
        "tool.html", tool=tool, PARTNER_IMAGE_SRC=get_partner_logo()
    )


# --------------------------------------
# Organizations & Groups Routes
# --------------------------------------


@dashboard_bp.route("/organizations")
@session_required
def organizations():
    orgs = ORGANIZATION.fetch_entities(limit=100, offset=0)
    for org in orgs:
        org["members"] = ORGANIZATION.list_members(member_kind="user", eid=org["id"])
        for member in org["members"][:5]:
            user = kutils.get_user(member[0])
            member.append(user.get("fullname", "STELAR User"))

    return render_template_with_s3(
        "organizations.html", PARTNER_IMAGE_SRC=get_partner_logo(), organizations=orgs
    )


@dashboard_bp.route("/organization/<organization_id>")
@session_required
def organization(organization_id):
    org = ORGANIZATION.get_entity(organization_id)
    org["members"] = ORGANIZATION.list_members(member_kind="user", eid=org["id"])
    # datasets = DATASET.search_entities()

    # for dataset in datasets[:4]:
    #     org["datasets"].append(DATASET.get_entity(dataset[0]))

    for member in org["members"][:5]:
        user = kutils.get_user(member[0])
        member.append(user.get("fullname", "STELAR User"))

    return render_template_with_s3(
        "organization.html", PARTNER_IMAGE_SRC=get_partner_logo(), organization=org
    )


# -------------------------------------------
# Admin Settings & Account Settings Routes
# -------------------------------------------


@dashboard_bp.route("/admin-settings")
@session_required
@admin_required
def adminSettings():
    return render_template_with_s3("cluster.html", PARTNER_IMAGE_SRC=get_partner_logo())


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
    return render_template_with_s3(
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


@dashboard_bp.route("/login/reset/<rs_token>/<user_id>", methods=["GET", "POST"])
def reset_password(rs_token, user_id):
    if "ACTIVE" in session and session["ACTIVE"]:
        return redirect(url_for("dashboard_blueprint.dashboard_index"))

    if request.method == "GET" and rs_token and user_id:
        payload = kutils.verify_reset_token(rs_token, user_id)

        if payload:
            if payload.get("exp"):
                expiration_time = datetime.fromtimestamp(payload.get("exp"))
                if expiration_time < datetime.now():
                    return redirect(url_for("dashboard_blueprint.login"))
                else:
                    return render_template("new_password.html")
            else:
                return redirect(url_for("dashboard_blueprint.login"))


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
                    email, vftoken=vftoken, id=new_uid, fullname=fullname
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
        session["PASSWORD_RESET_FLOW"] = False
        if "2FA_FLOW_IN_PROGRESS" in session and session["2FA_FLOW_IN_PROGRESS"]:
            return redirect(url_for("dashboard_blueprint.verify_2fa"))
        if "ACTIVE" in session and session["ACTIVE"]:
            return redirect(url_for("dashboard_blueprint.dashboard_index"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

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

                # Introspect the token to get user details
                userinfo = kutils.get_user_by_token(token["access_token"])

                if userinfo:
                    session["USER_NAME"] = userinfo.get("name")
                    session["USER_EMAIL"] = userinfo.get("email")
                    session["USER_EMAIL_VERIFIED"] = userinfo.get(
                        "email_verified", False
                    )
                    session["USER_USERNAME"] = userinfo.get("preferred_username")
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
