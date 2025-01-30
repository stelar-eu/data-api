import random
import re
import smtplib
import ssl

import pyotp
from apiflask import APIBlueprint
from email_validator import EmailNotValidError, validate_email
from flask import current_app, jsonify, request, session
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError

import kutils
import sql_utils
from routes.dashboard import session_required
from src.auth import auth, security_doc

"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to configuring the settings
    for a user account.
"""

# The tasks operations blueprint for all operations related to the lifecycle of `tasks
settings_bp = APIBlueprint("settings_blueprint", __name__, enable_openapi=False)


# Function to validate password strength
def validate_password_strength(password):
    """
    Validates that the password has at least:
    - 8 characters
    - One uppercase letter
    - One number
    - One special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."

    return True, ""


# Change password route (POST-only)
@settings_bp.route("/change-password", methods=["POST"])
@session_required
def change_password():
    """
    POST-only route to change the user's password.
    Looks for oldPassword, newPassword, newPasswordRepeat in the request form.
    """

    # Fetch Keycloak configuration from Flask app config
    config = current_app.config["settings"]

    # Initialize KeycloakOpenID client
    keycloak_openid = kutils.initialize_keycloak_openid()

    # Initialize KeycloakAdmin client

    keycloak_admin = kutils.init_admin_client_with_credentials()

    # Check if the user is logged in
    if "ACTIVE" not in session or not session["ACTIVE"]:
        return (
            jsonify(
                {"success": False, "message": "User not logged in", "error_code": 401}
            ),
            401,
        )

    # Get the form data
    old_password = request.form.get("oldPassword")
    new_password = request.form.get("newPassword")
    new_password_repeat = request.form.get("repeatNewPassword")

    # Ensure none of the fields are empty
    if not old_password or not new_password or not new_password_repeat:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "All fields are required",
                    "error_code": 400,
                }
            ),
            400,
        )

    # Check if new password matches its repeated version
    if new_password != new_password_repeat:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "New password and repeat password do not match",
                    "error_code": 2,
                }
            ),
            400,
        )

    # Validate the new password strength
    valid, message = validate_password_strength(new_password)
    if not valid:
        return jsonify({"success": False, "message": message, "error_code": 3}), 400

    # Perform the password change via Keycloak
    try:
        token = session.get("access_token")

        # Authenticate the user using the old password to ensure it's correct
        user_info = keycloak_openid.userinfo(token)
        email = user_info.get("email")

        # Verify the old password by requesting a token
        keycloak_openid.token(
            email, old_password
        )  # If this fails, old password is wrong

        # Perform the password update using the admin API
        keycloak_admin.set_user_password(
            user_id=session["KEYCLOAK_ID_USER"],
            password=new_password,
            temporary=False,  # Indicating this is a permanent password change
        )

        return jsonify(
            {
                "success": True,
                "message": "Password changed successfully",
                "error_code": 0,
            }
        )

    except KeycloakAuthenticationError:
        return (
            jsonify(
                {"success": False, "message": "Wrong old password", "error_code": 1}
            ),
            401,
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "An error occurred during the password change process",
                    "error_code": 500,
                }
            ),
            500,
        )


def send_otp_email(to_email):
    """
    Sends the OTP to the specified email address with a subject and sender name.
    SMTP settings are fetched from Flask's app config.
    """
    config = current_app.config["settings"]  # Fetch SMTP settings from app config

    smtp_server = config["SMTP_SERVER"]
    smtp_port = config["SMTP_PORT"]
    sender_email = config["SMTP_EMAIL"]
    sender_password = config["SMTP_PASSWORD"]

    # Generate the OTP
    otp = random.randint(100000, 999999)

    # Email subject and sender name
    subject = "Verify Your New Email Address"
    sender_name = "STELAR KLMS"

    # Ensure USER_NAME exists in session
    user_name = session.get("USER_USERNAME", "User")

    # Plain text message without headers (headers will be handled separately)
    plain_message = f"""\
Dear {user_name},

Your OTP to verify your email change is: {otp}.

If you did not request this change, please contact our support team.

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
        return otp

    except Exception as e:
        # Log the error
        raise Exception(f"Error sending OTP email: {str(e)}")


@settings_bp.route("/request-email-change", methods=["POST"])
@session_required
def request_email_change():
    """
    Send an OTP to the user's new email address for verification.
    Also checks if the email is already associated with another account.
    """

    # Fetch Keycloak configuration from Flask app config

    # Get the new email from the form data
    new_email = request.form.get("newEmail")

    if not new_email:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Email cannot be empty",
                    "error_code": 400,
                }
            ),
            400,
        )

    try:
        # Validate and normalize the email
        valid = validate_email(new_email)
        new_email = valid.email  # Normalized form of the eamil
    except EmailNotValidError as e:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Please provide a valid email",
                    "error_code": 400,
                }
            ),
            400,
        )

    # Initialize KeycloakAdmin client
    keycloak_admin = kutils.init_admin_client_with_credentials()

    # Check if the email is already in use by another user
    try:
        existing_users = keycloak_admin.get_users({"email": new_email})

        # If a user with this email already exists, return an error
        if existing_users:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "This email is already associated with another account.",
                        "error_code": 409,
                    }
                ),
                409,
            )

    except Exception as e:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Error checking email: {str(e)}",
                    "error_code": 500,
                }
            ),
            500,
        )

    # Store the new email in the session (for simplicity, also no database is needed)
    session["new_email"] = new_email

    try:
        otp = send_otp_email(new_email)  # Send the OTP email
        session["email_change_otp"] = otp
        return jsonify(
            {"success": True, "message": "OTP sent to your new email address."}
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"Failed to send email: {str(e)}",
                    "error_code": 500,
                }
            ),
            500,
        )


@settings_bp.route("/verify-email-otp", methods=["POST"])
@session_required
def verify_email_otp():
    """
    Verify the OTP entered by the user. If valid, update the user's email in Keycloak.
    """
    # Fetch the user ID and current session data
    user_id = session.get("KEYCLOAK_ID_USER")
    stored_otp = session.get("email_change_otp")
    new_email = session.get("new_email")

    # Get the OTP entered by the user
    user_otp = request.form.get("otp")

    if not user_otp or not new_email or not stored_otp:
        return (
            jsonify(
                {"success": False, "message": "Invalid request", "error_code": 400}
            ),
            400,
        )

    # Check if the OTP matches
    if int(user_otp) != stored_otp:
        return (
            jsonify({"success": False, "message": "Invalid OTP", "error_code": 401}),
            401,
        )

    try:
        # Initialize KeycloakAdmin client
        config = current_app.config["settings"]
        keycloak_admin = kutils.init_admin_client_with_credentials()

        # Update the user's email using Keycloak Admin API
        keycloak_admin.update_user(
            user_id=user_id, payload={"email": new_email, "emailVerified": True}
        )

        # Update the session with the new email
        session["USER_EMAIL"] = new_email

        # Clear the OTP and new email from the session
        session.pop("email_change_otp", None)
        session.pop("new_email", None)

        return jsonify({"success": True, "message": "Email updated successfully."})

    except Exception as e:
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"An error occurred: {str(e)}",
                    "error_code": 500,
                }
            ),
            500,
        )


@settings_bp.route("/generate-2fa", methods=["GET"])
@session_required
def generate_2fa_key():
    if kutils.user_has_2fa(session.get("KEYCLOAK_ID_USER")):
        return jsonify(
            {"success": False, "message": "2FA is already enabled for this user."}
        )

    secret, qrcode = kutils.generate_2fa_token(session.get("KEYCLOAK_ID_USER"))

    if secret and qrcode:
        session["TWO_FACTOR_TEMP_SECRET"] = secret
        return jsonify({"success": True, "qr": qrcode})


@settings_bp.route("/validate-2fa-activation", methods=["POST"])
@session_required
def validate_2fa_activation():
    """
    Validate the activation of 2FA (Two-Factor Authentication) for the user.

    This endpoint expects a POST request with a JSON body containing a "token" field.
    It verifies the provided token against the temporary 2FA secret stored in the session.
    If the token is valid, it stores the 2FA secret in the database and updates the session.

    Returns:
        JSON response indicating the success or failure of the 2FA activation process.
        - If successful: {"success": True, "message": "2FA activated successfully."}
        - If failed to activate: {"success": False, "message": "Failed to activate 2FA."}
        - If no temp secret in session: {"success": False, "message": "No 2FA activation in progress."}
    """
    if kutils.user_has_2fa(session.get("KEYCLOAK_ID_USER")):
        return jsonify(
            {"success": False, "message": "2FA is already enabled for this user."}
        )

    if session.get("TWO_FACTOR_TEMP_SECRET"):
        token = request.json.get("token", "").strip()
        secret = session.get("TWO_FACTOR_TEMP_SECRET")
        if kutils.is_2fa_otp_valid(secret, token):
            if kutils.activate_2fa(
                session.get("KEYCLOAK_ID_USER"), session.get("TWO_FACTOR_TEMP_SECRET")
            ):
                return jsonify(
                    {"success": True, "message": "2FA activated successfully."}
                )
            else:
                return jsonify({"success": False, "message": "Failed to activate 2FA."})
        else:
            return jsonify({"success": False, "message": "Failed to activate 2FA."})
    else:
        return jsonify({"success": False, "message": "No 2FA activation in progress."})


@settings_bp.route("/check-2fa-state", methods=["GET"])
@session_required
def check_2fa_state():
    """
    Validates the 2FA state for the current user session.
    This endpoint checks whether two-factor authentication (2FA) is enabled for the user associated with the current session.
    It does not validate an OTP token but rather checks the 2FA status.

    Returns:
        JSON response indicating whether 2FA is enabled for the user or if there is no valid session.
    """
    if session.get("KEYCLOAK_ID_USER"):
        if kutils.user_has_2fa(session.get("KEYCLOAK_ID_USER")):
            return jsonify(
                {"success": True, "message": "2FA is enabled for this user."}
            )
        else:
            return jsonify(
                {"success": False, "message": "2FA is not enabled for this user."}
            )

    else:
        return jsonify({"success": False, "message": "No valid session."})


@settings_bp.route("/validate-2fa-otp", methods=["POST"])
@session_required
def validate_2fa_otp():
    """
    Validates the 2FA OTP token provided by the user.

    This endpoint is used to validate the One-Time Password (OTP) token for two-factor authentication (2FA).
    It expects a JSON payload with the OTP token.

    Returns:
        JSON response indicating whether the OTP token is valid or not.
    """
    token = request.json.get("token", "").strip()

    if kutils.validate_2fa_otp(session.get("KEYCLOAK_ID_USER"), token):
        return jsonify({"success": True, "message": "2FA OTP is valid."})
    else:
        return jsonify({"success": False, "message": "Invalid 2FA OTP."})


@settings_bp.route("/disable-2fa", methods=["POST"])
@session_required
def disable_2fa():
    """
    Disable 2FA for the current user.

    This endpoint disables two-factor authentication (2FA) for the user associated with the current session.
    It does not require any additional data in the request, as it only disables 2FA for the current user.

    Returns:
        JSON response indicating the success or failure of the 2FA deactivation process.
    """
    if kutils.disable_2fa(session.get("KEYCLOAK_ID_USER")):
        return jsonify({"success": True, "message": "2FA disabled successfully."})
    else:
        return jsonify({"success": False, "message": "Failed to disable 2FA."})
