import datetime
import hashlib
import logging

# FOR TESTING ONLY!!!
import os
import random
import re
import smtplib
import ssl
import time
from datetime import datetime, timedelta
from functools import wraps
from math import ceil

import requests
from apiflask import APIBlueprint
from email_validator import EmailNotValidError, validate_email
from flask import (
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from keycloak import KeycloakAdmin, KeycloakOpenID

import cutils
import kutils
import wxutils
from auth import admin_required

dashboard_bp = APIBlueprint("dashboard_blueprint", __name__, enable_openapi=False)


logging.basicConfig(level=logging.DEBUG)


def render_template_with_s3(template_name, **kwargs):
    """
    Helper function to include the S3_CONSOLE_URL in all templates.
    """
    config = current_app.config["settings"]
    # Add the S3_CONSOLE_URL to the kwargs
    kwargs["S3_CONSOLE_URL"] = config.get("S3_CONSOLE_URL", "#")
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
        if not access_token or not kutils.introspect_token(access_token):
            keycloak_openid = kutils.initialize_keycloak_openid()
            # Revoke refresh token to log out
            try:
                keycloak_openid.logout(session["refresh_token"])
            except Exception as e:
                pass

            session.clear()
            # Clear local session and redirect to the login page
            flash("Session Expired, Please Login Again", "warning")
            return redirect(url_for("dashboard_blueprint.login", next=request.url))

        # If token is valid, continue with the requested function
        return f(*args, **kwargs)

    return decorated_function


# Home page (redirect target after login)
@dashboard_bp.route("/")
@session_required
def dashboard_index():
    return render_template_with_s3("index.html", PARTNER_IMAGE_SRC=get_partner_logo())


# Signup Route
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
        if not re.match(
            r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password
        ):
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
        username_base = re.sub(r"\d", "", email.split("@")[0])
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
            except ValueError:
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
    except:
        pass
    return render_template_with_s3(
        "settings.html",
        PARTNER_IMAGE_SRC=get_partner_logo(),
        TWO_FACTOR_AUTH=TWO_FACTOR_AUTH,
    )


@dashboard_bp.route("/workflows")
@session_required
def workflows():

    # Retrieve list of WFs from DB
    wf_metadata = wxutils.get_workflows()

    if wf_metadata is not None and wf_metadata != []:
        status_counts = {}
        monthly_counts = {}

        for wf in wf_metadata:
            # Count workflow status for pie chart
            status = wf["state"]
            status_counts[status] = status_counts.get(status, 0) + 1

            # Count workflows per month for bar chart
            start_date = wf["start_date"]
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
            "workflows.html",
            workflows=wf_metadata,
            status_counts=status_counts,
            monthly_counts=monthly_counts,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )

    else:
        return render_template_with_s3(
            "workflows.html",
            workflows={},
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )


@dashboard_bp.route("/workflows/<workflow_id>")
@session_required
def workflow(workflow_id):
    # Basic input validation
    if not workflow_id:
        return redirect(url_for("dashboard_blueprint.datasets"))

    wf_metadata = wxutils.get_workflow_process(workflow_id)
    tasks = wxutils.get_workflow_tasks(workflow_id)

    if wf_metadata:
        # Sort tasks based on start date
        if tasks and isinstance(tasks, list):
            tasks = sorted(tasks, key=lambda x: x["start_date"])
        try:
            package_id = wf_metadata["tags"].get("package_id")
        except:
            package_id = "Not specified"

        return render_template_with_s3(
            "workflow.html",
            workflow_id=workflow_id,
            PARTNER_IMAGE_SRC=get_partner_logo(),
            wf_metadata=wf_metadata,
            wf_tasks=tasks if tasks and isinstance(tasks, list) else None,
            package_id=package_id,
        )
    else:
        return redirect(url_for("dashboard_blueprint.login"))


@dashboard_bp.route("/task/<workflow_id>/<task_id>")
@session_required
def task(workflow_id, task_id):
    # Basic input validation
    if not workflow_id or not task_id:
        return redirect(url_for("dashboard_blueprint.login"))

    try:
        task_metadata = wxutils.get_task_metadata(task_id=task_id)

        # Do not allow mismatch between given wf and actual wf
        if task_metadata.get("workflow_exec_id") != workflow_id:
            return redirect(url_for("dashboard_blueprint.login"))

        input_metadata = wxutils.get_task_input_json(
            task_id=task_id, show_resource_ids=True
        )
        logs_metadata = wxutils.get_task_info(task_id=task_id)

        return render_template_with_s3(
            "task.html",
            PARTNER_IMAGE_SRC=get_partner_logo(),
            task_id=task_id,
            workflow_id=workflow_id,
            task_metadata=task_metadata,
            task_input=input_metadata,
            logs=logs_metadata,
        )
    except Exception as e:
        logging.debug(str(e))
        return redirect(url_for("dashboard_blueprint.login"))


@dashboard_bp.route("/datasets", methods=["GET", "POST"])
@dashboard_bp.route("/datasets/page/<page_number>", methods=["GET", "POST"])
@dashboard_bp.doc(False)
@session_required
def datasets(page_number=None):
    limit = 10
    page_number = int(page_number) if page_number and page_number.isdigit() else 1
    offset = limit * (page_number - 1) if page_number > 0 else 0

    if request.method == "POST":
        keyword = request.form.get("q", "").strip()

        if not re.match(r"^\w+$", keyword):
            return redirect(url_for("dashboard_blueprint.datasets"))

        try:
            # Search for datasets using the keyword
            datasets = cutils.search_packages(
                keyword=keyword, limit=limit, offset=offset, expand_mode=False
            )
            count_pkg = len(datasets)
            total_pages = ceil(count_pkg / limit) if count_pkg > 0 else 1

            return render_template_with_s3(
                "datasets.html",
                datasets=datasets,
                page_number=page_number,
                total_pages=total_pages,
                PARTNER_IMAGE_SRC=get_partner_logo(),
                search_keyword=keyword,
            )
        except Exception as e:
            flash(f"Error while searching datasets: {str(e)}", "error")
            return redirect(url_for("dashboard_blueprint.datasets"))
    else:
        # Handle default GET request
        try:
            datasets = cutils.list_packages(
                limit=limit, offset=offset, expand_mode=True
            )
        except Exception as e:
            datasets = []
            flash(f"Error loading datasets: {str(e)}", "error")

        try:
            count_pkg = int(cutils.count_packages())
            total_pages = ceil(count_pkg / limit) if count_pkg > 0 else 1
        except Exception:
            total_pages = 1

        return render_template_with_s3(
            "datasets.html",
            datasets=datasets,
            page_number=page_number,
            total_pages=total_pages,
            PARTNER_IMAGE_SRC=get_partner_logo(),
        )


@dashboard_bp.route("/datasets/<dataset_id>", methods=["GET", "POST"])
@session_required
def dataset_detail(dataset_id):
    if request.method == "POST":
        if request.form.get("dataset_delete"):
            try:
                id = request.form.get("dataset_delete")
                if id == dataset_id:
                    cutils.delete_package(id)
                    return redirect(url_for("dashboard_blueprint.datasets"))
            except:
                return redirect(url_for("dashboard_blueprint.datasets"))
        else:
            return redirect(url_for("dashboard_blueprint.datasets"))
    else:
        metadata_data = None
        try:
            metadata_data = cutils.get_package(id=dataset_id)
        except ValueError as e:
            return redirect(url_for("dashboard_blueprint.datasets"))
        except Exception as e:
            return redirect(url_for("dashboard_blueprint.datasets"))

        if metadata_data:
            return render_template_with_s3(
                "dataset_view.html",
                dataset=metadata_data,
                PARTNER_IMAGE_SRC=get_partner_logo(),
            )
        else:
            return redirect(url_for("dashboard_blueprint.datasets"))


@dashboard_bp.route("/resource/<resource_id>")
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
            return redirect(url_for("dashboard_blueprint.datasets"))
    else:
        return redirect(url_for("dashboard_blueprint.datasets"))


@dashboard_bp.route("/admin-settings")
@session_required
@admin_required
def adminSettings():
    return render_template_with_s3("cluster.html", PARTNER_IMAGE_SRC=get_partner_logo())


@dashboard_bp.route("/login/verify", methods=["GET", "POST"])
def verify_2fa(next_url=None):
    if request.method == "GET":
        if "ACTIVE" in session and session["ACTIVE"]:
            return redirect(url_for("dashboard_blueprint.dashboard_index"))
        else:
            return render_template("2fa.html", PARTNER_IMAGE_SRC=get_partner_logo())
    elif request.method == "POST":
        token = request.form.get("token")
        if token:
            try:
                kutils.validate_2fa_otp(session.get("KEYCLOAK_ID_USER"), token)
                session["ACTIVE"] = True
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
                    return render_template("reset_password.html")
            else:
                return redirect(url_for("dashboard_blueprint.login"))


####################################
# Login Route
####################################
@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles the Authentication process of a user given his credentials.
    Talks with the specified Keycloak instance to authenticate the user and fetch
    his info (roles, name, username, etc). Inits an active session.
    """
    keycloak_openid = kutils.initialize_keycloak_openid()

    EMPTY_EMAIL_ERROR = False
    EMPTY_PASSWORD_ERROR = False
    LOGIN_ERROR = False
    INACTIVE_ERROR = False

    # Check if the user is already logged in and redirect him to console home page if so
    if request.method == "GET":
        session["PASSWORD_RESET_FLOW"] = False
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
                token = keycloak_openid.token(email, password)
                session["access_token"] = token["access_token"]
                session["refresh_token"] = token["refresh_token"]

                # Introspect the token to get user details
                userinfo = keycloak_openid.introspect(token["access_token"])

                if userinfo:
                    session["USER_NAME"] = userinfo.get("name")
                    session["USER_EMAIL"] = userinfo.get("email")
                    session["USER_USERNAME"] = userinfo.get("preferred_username")
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
                        return redirect(url_for("dashboard_blueprint.verify_2fa"))

                    session["ACTIVE"] = True
                    if next_url:
                        return redirect(next_url)
                    else:
                        return redirect(url_for("dashboard_blueprint.dashboard_index"))
                else:
                    LOGIN_ERROR = True
            except Exception as e:
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


####################################
# Logout Route
####################################
@dashboard_bp.route("/logout")
def logout():
    if "ACTIVE" not in session or not session["ACTIVE"]:
        return redirect(url_for("dashboard_blueprint.login"))

    keycloak_openid = kutils.initialize_keycloak_openid()

    # Revoke refresh token to log out
    try:
        keycloak_openid.logout(session["refresh_token"])
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
