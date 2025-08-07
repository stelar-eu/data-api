import random
import re
import smtplib
import ssl
import logging

from apiflask import APIBlueprint
from email_validator import EmailNotValidError, validate_email
from flask import current_app, jsonify, request, session, make_response, url_for
from keycloak.exceptions import KeycloakAuthenticationError
from exceptions import InternalException, InvalidError
from routes.generic import render_api_output
import schema
import kutils
from routes.dashboard import session_required
from mailing import send_otp_email
from PIL import Image
from io import BytesIO
import os

"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to configuring the settings
    for a user account.
"""

# The tasks operations blueprint for all operations related to the lifecycle of `tasks
settings_bp = APIBlueprint("settings_blueprint", __name__, enable_openapi=False)

logger = logging.getLogger(__name__)


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
@settings_bp.input(schema.ChangePassword, location="form")
@session_required
@render_api_output(logger)
def change_password(form_data):
    """
    POST-only route to change the user's password.
    Looks for oldPassword, newPassword, newPasswordRepeat in the request form.
    """
    # Get the form data from validated form_data
    old_password = form_data.get("oldPassword")
    new_password = form_data.get("newPassword")
    new_password_repeat = form_data.get("repeatNewPassword")

    # Check if new password matches its repeated version
    if new_password != new_password_repeat:
        raise InvalidError("New password and its confirmation do not match.")

    # Validate the new password strength
    valid, message = validate_password_strength(new_password)
    if not valid:
        raise InvalidError(f"Password does not meet minimum requirements. {message}")

    token = session.get("access_token")

    # Authenticate the user using the old password to ensure it's correct
    user_info = kutils.get_user_by_token(token)
    email = user_info.get("email")

    # Verify the old password by requesting a token
    kutils.get_token(email, old_password)  # If this fails, old password is wrong

    # Perform the password update using the admin API
    kutils.set_user_password(
        user_id=session.get("KEYCLOAK_ID_USER"),
        password=new_password,
        temporary=False,  # Set to False to make it a permanent password
    )

    if session.get("REMEMBER_ME", False):
        # If the user has opted for "Remember Me", update the session with the new password
        session["USER_PASSWORD"] = new_password


@settings_bp.route("/request-email-change", methods=["POST"])
@settings_bp.input(schema.NewEmail, location="form")
@render_api_output(logger)
@session_required
def request_email_change(form_data):
    """
    Send an OTP to the user's new email address for verification.
    Also checks if the email is already associated with another account.
    """
    # Get the new email from the form data
    new_email = form_data.get("newEmail")

    try:
        # Validate and normalize the email
        valid = validate_email(new_email)
        new_email = valid.email  # Normalized form of the email
    except EmailNotValidError as e:
        raise InvalidError(f"Invalid email address: {str(e)}")

    # This will throw a ConflictError if the email is not unique
    kutils.email_unique(new_email)

    # Store the new email in the session (for simplicity, also no database is needed)
    session["new_email"] = new_email
    try:
        otp = send_otp_email(new_email)  # Send the OTP email
        session["email_change_otp"] = otp
        return {"message": "OTP sent to your new email address."}
    except Exception as e:
        raise InternalException(f"Failed to send OTP email: {str(e)}") from e


@settings_bp.route("/verify-email-otp", methods=["POST"])
@settings_bp.input(schema.OTPVerification, location="form")
@render_api_output(logger)
@session_required
def verify_email_otp(form_data):
    """
    Verify the OTP entered by the user. If valid, update the user's email in Keycloak.
    """
    # Fetch the user ID and current session data
    user_id = session.get("KEYCLOAK_ID_USER")
    stored_otp = session.get("email_change_otp")
    new_email = session.get("new_email")

    # Get the OTP entered by the user
    user_otp = form_data.get("otp")

    if not user_otp or not new_email or not stored_otp:
        raise InvalidError("Invalid State. No OTP verification in progress")

    # Check if the OTP matches
    if int(user_otp) != stored_otp:
        raise InvalidError("Invalid OTP. Please try again.")

    # If the OTP is valid, update the user's email in Keycloak
    kutils.update_user(email=new_email, user_id=user_id, email_verified=True)

    # Update the session with the new email
    session["USER_EMAIL"] = new_email
    # Clear the OTP and new email from the session
    session.pop("email_change_otp")
    session.pop("new_email")

    return {"message": "Email updated successfully."}


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


@settings_bp.route("/avatar", methods=["POST"])
@session_required
def upload_avatar():

    username = session.get("USER_USERNAME")

    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file provided."}), 400

    file = request.files["file"]

    file.seek(0, os.SEEK_END)
    if file.tell() > 2 * 1024 * 1024:  # 2MB size limit
        return (
            jsonify({"success": False, "message": "File size exceeds 2MB limit."}),
            400,
        )
    file.seek(0)

    try:
        image = Image.open(file)
    except Exception:
        return jsonify({"success": False, "message": "Invalid image file."}), 400

    if image.format not in ["PNG", "JPEG", "JPG"]:
        return (
            jsonify(
                {"success": False, "message": "Only PNG and JPEG files are allowed."}
            ),
            400,
        )

    # Compress and convert image to PNG
    output = BytesIO()
    if image.mode in ("RGBA", "P"):
        image = image.convert("RGB")
    image.save(output, format="PNG", optimize=True)
    output.seek(0)

    avatar_dir = os.path.join(current_app.root_path, "static", "avatars")
    if not os.path.exists(avatar_dir):
        os.makedirs(avatar_dir)

    avatar_path = os.path.join(avatar_dir, f"{username}.png")
    with open(avatar_path, "wb") as f:
        f.write(output.read())

    session["AVATAR"] = url_for("static", filename=f"avatars/{username}.png")
    return jsonify({"success": True, "message": "Avatar uploaded successfully."}), 200


@settings_bp.route("/avatar", methods=["DELETE"])
@session_required
def delete_avatar():
    username = session.get("USER_USERNAME")
    avatar_dir = os.path.join(current_app.root_path, "static", "avatars")
    avatar_path = os.path.join(avatar_dir, f"{username}.png")

    if os.path.exists(avatar_path):
        try:
            os.remove(avatar_path)
            session.pop("AVATAR")
            return (
                jsonify({"success": True, "message": "Avatar deleted successfully."}),
                200,
            )
        except Exception as e:
            return (
                jsonify(
                    {"success": False, "message": f"Error deleting avatar: {str(e)}"}
                ),
                500,
            )
    else:
        return jsonify({"success": True, "message": "No avatar to delete."}), 200


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
                return (
                    jsonify({"success": False, "message": "Failed to activate 2FA."}),
                    403,
                )
        else:
            return (
                jsonify({"success": False, "message": "Invalid OTP."}),
                401,
            )
    else:
        return (
            jsonify({"success": False, "message": "No 2FA activation in progress."}),
            400,
        )


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
        return make_response(
            jsonify({"success": True, "message": "2FA OTP is valid."}), 200
        )
    else:
        return make_response(
            jsonify({"success": False, "message": "Invalid 2FA OTP."}), 403
        )


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
        return {"message": "2FA disabled successfully.", "success": True}, 200
    else:
        return {"message": "2FA failed to disable.", "success": False}, 400
