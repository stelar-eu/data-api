import base64
import datetime
import logging
import smtplib
import ssl
from io import BytesIO
from functools import wraps
import flask
import jwt
import pyotp
import json
import qrcode
from flask import current_app, session, url_for
from keycloak import (
    KeycloakAuthenticationError,
    KeycloakGetError,
    KeycloakPostError,
    KeycloakPutError,
    KeycloakDeleteError,
    KeycloakConnectionError,
    KeycloakInvalidTokenError,
)
import sql_utils
from backend.ckan import ckan_request
from backend.pgsql import execSql
from backend.kc import KEYCLOAK_ADMIN_CLIENT, KEYCLOAK_OPENID_CLIENT
from qutils import REGISTRY
from backend.redis import REDIS

from exceptions import (
    APIException,
    AuthenticationError,
    AuthorizationError,
    BackendError,
    InternalException,
    InvalidError,
    NotFoundError,
    ConflictError,
)
from utils import is_valid_uuid, validate_email

logger = logging.getLogger(__name__)


def raise_keycloak_error(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (
            KeycloakAuthenticationError,
            KeycloakGetError,
            KeycloakPostError,
            KeycloakPutError,
            KeycloakDeleteError,
            KeycloakConnectionError,
            KeycloakInvalidTokenError,
        ) as e:
            logger.error(
                "Keycloak error in %s: %s", func.__name__, str(e), exc_info=True
            )
            response_code = getattr(e, "response_code", None)
            detail_message = ""
            if hasattr(e, "response_body") and e.response_body:
                try:
                    # Attempt to decode and extract the detailed message from the response body.
                    error_detail = json.loads(e.response_body.decode("utf-8"))
                    detail_message = error_detail.get("message", str(e))
                except Exception:
                    detail_message = str(e.response_body)
            else:
                detail_message = str(e)

            if response_code == 409:
                raise ConflictError(
                    message="Conflict: Duplicate resource", detail=detail_message
                ) from e
            elif response_code == 400:
                raise InvalidError(
                    message="Bad Request: Invalid data sent to Keycloak",
                    detail=detail_message,
                ) from e
            elif response_code == 404:
                raise NotFoundError(
                    message="Resource not found in Keycloak",
                    detail=detail_message,
                ) from e
            elif response_code == 401:
                raise AuthenticationError(
                    message="Authorization using the provided credentials failed",
                    detail=detail_message,
                ) from e
            else:
                raise InternalException(message=detail_message) from e

    return wrapper


def email_username_unique(username, email):
    username_unique(username=username)
    email_unique(email=email)


def convert_iat_to_date(timestamp):
    date = None
    if timestamp:
        date = datetime.datetime.fromtimestamp(timestamp / 1000.0).isoformat()
        return date
    else:
        return None


@raise_keycloak_error
def username_unique(username):
    # Check for existing users with the same username
    existing_users = KEYCLOAK_ADMIN_CLIENT().get_users({"username": username})

    if existing_users:
        raise ConflictError(f"A user with the username '{username}' already exists.")


@raise_keycloak_error
def email_unique(email):
    # Check for existing users with the same email
    existing_emails = KEYCLOAK_ADMIN_CLIENT().get_users({"email": email})
    if existing_emails:
        raise ConflictError(f"A user with the email '{email}' already exists.")


def generate_reset_token(user_id, expiration_minutes=30):
    """
    Generates a JWT token with an expiration.
    :param user_id: The unique identifier for the user.
    :param expiration_minutes: Token validity period in minutes.
    :return: Encoded JWT token as a string.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.now() + datetime.timedelta(minutes=expiration_minutes),
    }
    token = jwt.encode(payload, user_id, algorithm="HS256")
    return token


@raise_keycloak_error
def reset_password_init_flow(email):
    """Sends an email with a reset link for the account linked with the
    given email address. Initiates the flow for reseting the password.

    Args:
        - email: The address of the account
    Returns:
        - True: if the initialization of the reset process was succesful

    Raises:
        -
    """
    user_rep = KEYCLOAK_ADMIN_CLIENT().get_users(query={"email": email})
    if user_rep:
        kuuid = user_rep[0].get("id")
        if is_valid_uuid(kuuid):
            send_reset_password_email(
                to_email=email,
                rstoken=generate_reset_token(user_rep[0].get("id")),
                user_id=user_rep[0].get("id"),
                fullname=user_rep[0].get("firstName")
                + " "
                + user_rep[0].get("lastName"),
            )
            return True


def verify_reset_token(token, user_id):
    """
    Verifies the JWT token and extracts the payload.
    :param token: The JWT token to verify.
    :param user_id: The id of the user to verify the token for.
    :return: Decoded payload if valid, None if invalid or expired.
    """
    try:
        payload = jwt.decode(token, user_id, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@raise_keycloak_error
def introspect_token(access_token):
    """
    Introspects the given access token to check if it's valid and active.
    Returns True if the token is valid, False if the token is invalid or expired.
    """

    introspect_response = KEYCLOAK_OPENID_CLIENT().introspect(access_token)
    # Check if the token is active
    if introspect_response.get("active", False):
        return introspect_response
    else:
        raise AuthenticationError(message="Token is invalid or expired")


def introspect_admin_token(access_token):
    """
    Introspects the given access token to check if it's valid, active,
    and if the user has the admin role.
    Returns True if the token is valid and admin.
    Raises TokenExpiredError if the token is inactive/expired.
    Raises AuthorizationError if the token is active but not for an admin user.
    """
    introspect_response = introspect_token(access_token)

    # Optionally check for realm_access if needed
    if not introspect_response.get("realm_access", False):
        raise AuthenticationError(
            message="Token is missing realm access information",
        )

    # Check if the token has admin privileges.
    is_admin_flag = introspect_response.get("is_admin", None)
    if is_admin_flag is None or not is_admin_flag:
        raise AuthorizationError(
            message="Bearer Token is not related to an admin user",
        )

    return True


def get_user_by_token(access_token):
    """
    Introspects the given access token to return the user information if the token is active
    Returns the user json if the token is valid, False if the token is invalid or expired.
    """
    return introspect_token(access_token)


def is_token_active(access_token):
    """
    Introspects the given access token to check if it's valid and active.
    Returns True if the token is valid, False if the token is invalid or expired.
    """

    introspect_response = KEYCLOAK_OPENID_CLIENT().introspect(access_token)
    # Check if the token is active
    if introspect_response.get("active", False):
        return introspect_response
    else:
        return False


def current_user():
    """Return the current user from the session or the request headers.

    When the 'Authorization' header is present in the request, the user is fetched using the access token in the header.
    else, the user is fetched using the access token stored in the session.

    NOTE: This is a bit fragile, since it assumes that the header 'Authorization' is always present in the request.
    Properly, a check would be needed.

    The user is saved in the flask.g context for the current request.

    Returns:
        dict: The user information.
    """
    if "current_user" not in flask.g:
        from flask import request

        logger.info("Fetching current user's info by token")
        match request.headers.get("Authorization", "").split(" "):
            case ["Bearer", access_token]:
                pass
            case _:
                access_token = session.get("access_token")

        flask.g.current_user = get_user_by_token(access_token=access_token)
    logger.info("User's info fetched from context")
    return flask.g.current_user


def current_token():
    """Return the current token from the session or the request headers.

    When the 'Authorization' header is present in the request, the user is fetched using the access token in the header.
    else, the user is fetched using the access token stored in the session.

    NOTE: This is a bit fragile, since it assumes that the header 'Authorization' is always present in the request.
    Properly, a check would be needed.

    Returns:
        dict: The token.
    """
    if "access_token" not in flask.g:
        from flask import request

        match request.headers.get("Authorization", "").split(" "):
            case ["Bearer", access_token]:
                pass
            case _:
                access_token = session.get("access_token")

        flask.g.access_token = access_token
    return flask.g.access_token


def user_has_2fa(user_id):
    if is_valid_uuid(user_id):
        return sql_utils.two_factor_user_has_2fa(user_id=user_id)


def stat_user_2fa(user_id):
    if is_valid_uuid(user_id):
        return sql_utils.stat_two_factor_for_user(user_id=user_id)


def generate_2fa_token(user_id):
    """
    Generates a 2FA token for a given user and returns the secret and QR code in Base64 format.
    Args:
        user_id (str): The UUID of the user for whom the 2FA token is being generated.
    Returns:
        tuple: A tuple containing the secret key (str) and the QR code image in Base64 format (str).
    Raises:
        AttributeError: If the user is not valid.
        ValueError: If the provided user_id is not a valid UUID.
    """
    if is_valid_uuid(user_id):
        try:
            secret = pyotp.random_base32()
            otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=get_user(user_id).get("username"), issuer_name="STELAR KLMS"
            )

            # Generate QR Code
            qr = qrcode.QRCode()
            qr.add_data(otp_uri)
            qr.make(fit=True)
            qr_img = qr.make_image(fill="black", back_color="white")

            # Convert to Base64
            buffer = BytesIO()
            qr_img.save(buffer, format="PNG")
            qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

            return secret, qr_base64
        except Exception as e:
            raise (f"Failed to generate 2FA token: {str(e)}")
    else:
        raise InvalidError(message=f"{user_id} is not a valid UUID")


def activate_2fa(user_id, secret):
    """
    Activates two-factor authentication for a user.

    Args:
        user_id (str): The UUID of the user.
        secret (str): The secret key for two-factor authentication.

    Returns:
        bool: True if the operation is successful.

    Raises:
        ValueError: If the user_id is not a valid UUID or the user is not found.
    """
    if is_valid_uuid(user_id) and get_user(user_id):
        if sql_utils.two_factor_auth_create(user_id=user_id, secret=secret):
            return True
        else:
            return False
    else:
        raise ValueError("Not valid UUID or User not found")


def is_2fa_otp_valid(secret, token):
    """
    Validate a 2FA OTP token for a given secret

    Args:
        secret (str): The secret key for the user.
        token (str): The OTP token to be validated.

    Returns:
        bool: True if the token is valid, False otherwise.
    """
    totp = pyotp.TOTP(secret)
    if totp.verify(token):
        return True
    else:
        return False


def validate_2fa_otp(user_id, token):
    """
    Validate a 2FA (Two-Factor Authentication) OTP (One-Time Password) for a given user.

    This function checks if the provided user ID is a valid UUID and if the user has 2FA enabled.
    If both conditions are met, it retrieves the user's 2FA secret and validates the provided OTP token.

    Args:
        user_id (str): The UUID of the user.
        token (str): The OTP token to be validated.

    Returns:
        bool: True if the OTP token is valid, False otherwise.

    Raises:
        ValueError: If the OTP does not match the secret key
        ValueError: If the provided user_id is not a valid UUID.
    """
    if is_valid_uuid(user_id):
        if sql_utils.two_factor_user_has_2fa(user_id=user_id):
            secret = sql_utils.two_factor_auth_retrieve(user_id=user_id).get(
                "two_factor_key"
            )
            if is_2fa_otp_valid(secret, token):
                return True
            else:
                raise ValueError("Not valid OTP")
    else:
        raise ValueError("Not valid UUID")


def disable_2fa(user_id):
    if is_valid_uuid(user_id):
        return sql_utils.two_factor_revoke(user_id=user_id)
    else:
        raise InvalidError(400, message=f"{user_id} is not a valid UUID")


@raise_keycloak_error
def refresh_access_token(refresh_token):
    """
    Refreshes the access token using the refresh token given as args.

    This function initializes the Keycloak OpenID client and uses the stored refresh token
    to obtain a new access token. If successful, it updates the session with the new
    access token and refresh token. In case of failure, it returns an appropriate error message.

    Args:
        - refresh_token: The refresh token to use.

    Returns:
        tuple: A tuple containing:
            - str or None: The refreshed access token if successful, otherwise None.
            - str or None: An error message if the refresh fails, otherwise None.
    """

    if not refresh_token:
        raise InvalidError(message="Missing refresh token.")

    token = KEYCLOAK_OPENID_CLIENT().refresh_token(
        refresh_token, grant_type="refresh_token"
    )
    return token


@raise_keycloak_error
def get_token(username, password):
    """
    Returns a token for a user in Keycloak by using username and password.

    Args:
        username: The username of the user in Keycloak.
        password: The secret password of the user in Keycloak.

    Returns:
        dict: The token dictionary containing the access_token and additional details.

    Raises:
        AuthenticationError: If the token could not be retrieved.
    """
    return KEYCLOAK_OPENID_CLIENT().token(username, password)


@raise_keycloak_error
def get_user_roles(user_id):
    """
    Fetches the roles assigned to a user with the given user_id using KeycloakAdmin object.

    :param user_id: The ID of the user whose roles are to be fetched.
    :return: A list of roles assigned to the user.
    """
    realm_roles = KEYCLOAK_ADMIN_CLIENT().get_realm_roles_of_user(user_id)

    if not realm_roles:
        return []

    # Filter out default roles and extract role names
    filtered_roles = [
        role["name"]
        for role in realm_roles
        if role.get("name") and role["name"] != "default-roles-master"
    ]

    return filtered_roles


@raise_keycloak_error
def get_role(role_id):
    """
    Fetches the role by ID from the Realm

    :param user_id: The ID or the name of the role to be fetched.
    :return: The role representation
    """

    if is_valid_uuid(role_id):
        role_rep = KEYCLOAK_ADMIN_CLIENT().get_realm_role_by_id(role_id)
    else:
        role_rep = KEYCLOAK_ADMIN_CLIENT().get_realm_role(role_id)

    return role_rep


@raise_keycloak_error
def get_realm_roles():
    """
    Returns the realm roles exluding the Keycloak default roles.
    """
    roles = KEYCLOAK_ADMIN_CLIENT().get_realm_roles(brief_representation=True)

    # Define a set of roles to exclude
    roles_to_exclude = {
        "offline_access",
        "uma_authorization",
        "create-realm",
        "default-roles-master",
    }

    # Filter the roles, excluding those in the roles_to_exclude set
    filtered_roles = [role for role in roles if role["name"] not in roles_to_exclude]

    return filtered_roles


@raise_keycloak_error
def create_user_with_password(
    username,
    email,
    first_name,
    last_name,
    password,
    enabled=True,
    temporary_password=False,
    attributes=None,
    email_verified=True,
):
    """
    Create a new user in Keycloak and set a password, ensuring username and email are unique.

    :param username: Username for the new user
    :param email: Email for the new user
    :param first_name: First name of the user
    :param last_name: Last name of the user
    :param password: Password for the new user
    :param enabled: Whether the user account should be enabled (default: True)
    :param temporary_password: If True, the password is marked as temporary
    :param attributes: Additional attributes to add to the user
    :param emailVerified: Boolean to mark the verification state of the email
    :return: The ID of the created user, or None if creation failed
    """
    # Validate that an email matches the RegEx
    validate_email(email=email)

    # Will raise ValueError if the username or email already exist.
    email_username_unique(username=username, email=email)

    user_payload = {
        "username": username,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": enabled,
        "emailVerified": email_verified,
        "attributes": attributes or {},
    }

    user_id = KEYCLOAK_ADMIN_CLIENT().create_user(payload=user_payload, exist_ok=False)

    if user_id:
        KEYCLOAK_ADMIN_CLIENT().set_user_password(
            user_id=user_id, password=password, temporary=temporary_password
        )

    # Create the twin user in CKAN
    create_ckan_user(username, user_id, email, first_name, last_name, password)

    # Sync the user default permission in QUAY
    sync_registry_user(user_id, username, email, [])

    return get_user(user_id)


def create_ckan_user(username, user_id, email, first_name, last_name, password):
    ckan_payload = {
        "name": username,
        "id": user_id,
        "fullname": f"{first_name} {last_name}",
        "email": email,
        "password": password,
    }

    try:
        obj = ckan_request("user_create", json=ckan_payload)
        logger.debug("CKAN Response: %s", obj)
    except Exception:
        KEYCLOAK_ADMIN_CLIENT().delete_user(user_id)
        raise

    # Promote the user to sysadmin in CKAN
    query = 'UPDATE public."user" SET sysadmin = %s WHERE id = %s'
    execSql(query, (True, user_id))


def sync_registry_user(username, user_id, email, roles):
    try:
        user = {
            "oauth_id": user_id,
            "username": username,
            "email": email,
            "groups": roles,
        }
        REGISTRY.sync_user_permissions(user)
    except:
        pass


def delete_ckan_user(username):
    # Delete user's API tokens
    query = 'DELETE FROM public.api_token WHERE user_id IN (SELECT id FROM public."user" WHERE name = %s)'
    execSql(query, (username,))
    # Remove references to user's ID where he was a creator
    query = "UPDATE public.package SET creator_user_id='__deleted__' WHERE creator_user_id IN (SELECT id FROM public.\"user\" WHERE name = %s)"
    execSql(query, (username,))
    # Finally, delete the user
    query = 'DELETE FROM public."user" WHERE name= %s'
    execSql(query, (username,))


def update_ckan_id(username, old_id, new_id):
    """
    Updates the CKAN user ID in the database.
    This function updates the user ID in the CKAN database for a given username and matches
    it with the ID the user has in Keycloak.

    Because CKAN uses the user id as a foreign key, we need to delete the API tokens
    associated with the old user ID before updating it to the new one. In this context
    we also need to invalidate the cached API tokens in Redis.

    Args:
        username (str): The username of the user to update.
        old_id (str): The old ID of the user.
        new_id (str): The new ID of the user.
    """
    # Invalidate the cached CKAN API tokens in Redis
    REDIS.delete("ckantoken:" + new_id)
    REDIS.delete("ckantoken:" + old_id)
    # Delete user's CKAN API tokens
    query = 'DELETE FROM public.api_token WHERE user_id IN (SELECT id FROM public."user" WHERE name = %s)'
    execSql(query, (username,))
    # Update the user ID in CKAN's database
    query = 'UPDATE public."user" SET id=%s WHERE name= %s'
    execSql(query, (new_id, username))


def update_user(
    user_id,
    first_name=None,
    last_name=None,
    email=None,
    enabled=None,
    email_verified=None,
):
    """
    Updates a user in the Keycloak realm by the given user ID.

    Parameters:
    - first_name (str, optional): The new first name for the user.
    - last_name (str, optional): The new last name for the user.
    - email (str, optional): The new email for the user.
    - enabled (bool, optional): Whether the user account should be enabled or disabled.

    Returns:
    - dict: The updated user data if successful, otherwise raises an exception.

    Raises:
    - ValueError: if the username or the email are not unique
    """

    # Prepare the update data dictionary with only the fields that are not None
    user_data = {}
    user_repr = get_user(user_id=user_id)

    if user_repr["username"] == "admin":
        raise InvalidError("Modifications to administrator account are not allowed")

    if first_name:
        user_data["firstName"] = first_name
    if last_name:
        user_data["lastName"] = last_name
    if email:
        # Validate that an email matches the RegEx
        validate_email(email=email)
        # Will raise ValueError if email not unique for other users not the user being updated itself
        if user_repr.get("email") != email:
            email_unique(email=email)

        user_data["email"] = email
    if enabled is not None:
        user_data["enabled"] = enabled

    if email_verified is not None:
        user_data["emailVerified"] = email_verified

    # Support both selecting user by UUID and by Username
    if not is_valid_uuid(user_id):
        user_id = KEYCLOAK_ADMIN_CLIENT().get_user_id(user_id)

    KEYCLOAK_ADMIN_CLIENT().update_user(user_id, user_data)

    updated_user_json = get_user(user_id=user_id)

    return updated_user_json


def sync_users():
    """
    Syncs users from Keycloak to CKAN and updates their roles.
    This function retrieves all users from Keycloak and checks if they exist in CKAN.
    If a user does not exist in CKAN, it creates the user and assigns the appropriate roles.
    """
    try:
        # Fetch all users from Keycloak
        kc_users = get_users_from_keycloak(offset=0, limit=0)
        ckan_users = ckan_request("user_list", params={"limit": 0})

        # Build mappings of users by username excluding "admin" and "ckan_admin"
        kc_users_map = {
            user["username"]: user
            for user in kc_users
            if user["username"] not in ["admin", "ckan_admin"]
        }
        ckan_users_map = {
            user["name"]: user
            for user in ckan_users
            if user["name"] not in ["admin", "ckan_admin"]
        }  # Assuming CKAN uses "name" as username

        # 1. Users present in Keycloak but not in CKAN
        keycloak_only = [
            user
            for username, user in kc_users_map.items()
            if username not in ckan_users_map
        ]

        # 2. Users that have the same username in both but their IDs do not match
        mismatched_ids = [
            {
                "username": username,
                "keycloak_id": kc_users_map[username]["id"],
                "ckan_id": ckan_users_map[username]["id"],
            }
            for username in kc_users_map.keys() & ckan_users_map.keys()
            if kc_users_map[username]["id"] != ckan_users_map[username]["id"]
        ]

        # 3. Users present in CKAN but not in Keycloak
        ckan_only = [
            user
            for username, user in ckan_users_map.items()
            if username not in kc_users_map
        ]

        # logger.info("Users in Keycloak but not in CKAN: %s", keycloak_only)
        # logger.info("Users with mismatched IDs: %s", mismatched_ids)
        # logger.info("Users in CKAN but not in Keycloak: %s", ckan_only)

        # Create users in CKAN for those present in Keycloak but not in CKAN
        for user in keycloak_only:
            try:
                create_ckan_user(
                    username=user["username"],
                    user_id=user["id"],
                    email=user["email"],
                    first_name=user["first_name"],
                    last_name=user["last_name"],
                    password="empty_pass",
                )
            except Exception as e:
                logger.error(
                    "Error while creating CKAN user for Keycloak user %s: %s",
                    user["username"],
                    str(e),
                )

        # Delete users in CKAN that are not in Keycloak
        for user in ckan_only:
            try:
                delete_ckan_user(user["name"])
            except Exception as e:
                logger.error(
                    "Error while deleting CKAN user %s: %s", user["name"], str(e)
                )

        # Update the mismatched IDs in CKAN
        for user in mismatched_ids:
            update_ckan_id(user["username"], user["ckan_id"], user["keycloak_id"])

        return {
            "keycloak_only": keycloak_only,
            "mismatched_ids": mismatched_ids,
            "ckan_only": ckan_only,
        }

    except Exception as e:
        logger.error("Error while syncing users: %s", str(e), exc_info=True)
        raise InternalException("Error while syncing users") from e


@raise_keycloak_error
def get_user(user_id):
    """
    Retrieve a user from Keycloak by user ID.
    It also returns the roles

    :param user_id: The ID of the user to retrieve (str). If None, returns None.
    :return: A dictionary representation of the user if found, otherwise None.
    """
    # Support both searching by UUID and by Username
    if is_valid_uuid(user_id):
        user_representation = KEYCLOAK_ADMIN_CLIENT().get_user(user_id)
    else:
        id = KEYCLOAK_ADMIN_CLIENT().get_user_id(user_id)
        user_representation = KEYCLOAK_ADMIN_CLIENT().get_user(id)

    if user_representation:
        creation_date = convert_iat_to_date(user_representation["createdTimestamp"])

        filtered_roles = get_user_roles(user_representation["id"])

        active_status = user_representation.get("enabled", False)
        email_verified = user_representation.get("emailVerified", False)

        user_info = {
            "username": user_representation.get("username"),
            "email": user_representation.get("email"),
            "fullname": f"{user_representation.get('firstName', '')} {user_representation.get('lastName', '')}".strip(),
            "first_name": user_representation.get("firstName"),
            "last_name": user_representation.get("lastName"),
            "joined_date": creation_date,
            "id": user_representation.get("id"),
            "roles": filtered_roles,
            "active": active_status,
            "email_verified": email_verified,
        }

        return user_info
    return None


@raise_keycloak_error
def delete_user(user_id):
    """
    Delete a user from Keycloak by user UUID.

    :param user_id: The UUID of the user to delete (str). If None, returns None.
    :return: A dictionary containing the UUID of the deleted user.
    """
    # Support both UUID and username
    if not is_valid_uuid(user_id):
        id = KEYCLOAK_ADMIN_CLIENT().get_user_id(user_id)
        user_id = KEYCLOAK_ADMIN_CLIENT().get_user(id)["id"]

    KEYCLOAK_ADMIN_CLIENT().delete_user(user_id)
    return {"id": user_id}


@raise_keycloak_error
def get_users_from_keycloak(offset, limit):
    """
    Retrieves a list of users from Keycloak with pagination and additional user details.

    Args:
        offset (int): The starting index for the users to retrieve.
        limit (int): The maximum number of users to retrieve. Use 0 to retrieve all users starting from offset.

    Returns:
        A list of user dictionaries containing user details.

    Raises:
        InvalidError: If invalid values for offset or limit are provided.
    """
    if offset < 0 or limit < 0:
        raise InvalidError("Limit and offset must be greater than 0.")

    query = {"first": offset} if limit == 0 else {"first": offset, "max": limit}

    users = KEYCLOAK_ADMIN_CLIENT().get_users(query=query)

    result = []
    for user in users:
        creation_date = convert_iat_to_date(user["createdTimestamp"])
        filtered_roles = get_user_roles(user["id"])
        active_status = user.get("enabled", False)

        user_info = {
            "username": user.get("username"),
            "email": user.get("email"),
            "fullname": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
            "first_name": user.get("firstName"),
            "last_name": user.get("lastName"),
            "joined_date": creation_date,
            "id": user.get("id"),
            "roles": filtered_roles,
            "active": active_status,
        }
        result.append(user_info)

    return result


def fetch_user_creation_date(user_id):
    """
    Fetches user creation date from Keycloak Admin API using client credentials access token.

    """
    try:
        user = get_user(user_id)
        data = user.get("joined_date")
        if data:
            return data
    except Exception as e:
        logger.debug(
            "Error while fetching user creation date: %s", str(e), exc_info=True
        )
        return None


@raise_keycloak_error
def assign_role_to_user(user_id, role_id):
    """
    Assigns realm role to user.

    Args:
    - user_id: The UUID of the user or the username.
    - role_id: The UUID of the realm role or the name of it.

    Returns:
    - dict(): The updated user represantation containing the new role
    """
    # Fetch the user representation
    user_rep = get_user(user_id)
    user_roles = get_user_roles(user_rep.get("id"))
    # Fetch the role representation
    role_rep = get_role(role_id)

    # Assign the role to the user if it is not already assigned
    if role_rep["name"] not in user_roles:
        KEYCLOAK_ADMIN_CLIENT().assign_realm_roles(user_rep["id"], [role_rep])

    user_rep = get_user(user_id)
    # We need to trigger the permissions sync for the registry.
    sync_registry_user(
        user_rep.get("username"),
        user_rep.get("id"),
        user_rep.get("email"),
        user_rep.get("roles"),
    )
    return user_rep


@raise_keycloak_error
def assign_roles_to_user(user_id, role_ids):
    """
    Assign multiple realm roles to a user.

    Args:
    - user_id: The UUID of the user or the username.
    - role_ids: A list of UUIDs or names of the realm roles to be assigned.

    Returns:
    - dict: The updated user representation containing the new roles.

    Raises:
    - ValueError: If the user or any role is not found.
    - AttributeError: If any role is already assigned to the user.
    """
    if not isinstance(role_ids, list):
        raise InvalidError("role_ids must be a list of role UUIDs or names.")

    # Fetch the user representation
    user_rep = get_user(user_id)
    user_roles = get_user_roles(user_rep.get("id"))

    # Fetch all roles representations
    roles_to_assign = []
    for role_id in role_ids:
        role_rep = get_role(role_id)
        # Check if the role is already assigned
        if role_rep["name"] not in user_roles:
            roles_to_assign.append(role_rep)

    # Assign roles to the user if there are new roles to assign
    if roles_to_assign:
        KEYCLOAK_ADMIN_CLIENT().assign_realm_roles(user_rep["id"], roles_to_assign)

    user_rep = get_user(user_id)
    # We need to trigger the permissions sync for the registry.
    sync_registry_user(
        user_rep.get("username"),
        user_rep.get("id"),
        user_rep.get("email"),
        user_rep.get("roles"),
    )
    return user_rep


@raise_keycloak_error
def patch_user_roles(user_id, role_ids):
    """
    Patch the roles of the user with new roles. Any roles not specified in the list will be removed.

    Args:
    - user_id: The UUID of the user or the username.
    - role_ids: A list of UUIDs or names of the realm roles to be assigned.

    Returns:
    - dict: The updated user representation containing the new roles.

    Raises:
    - ValueError: If the user or any role is not found.
    - AttributeError: If any role is already assigned to the user.
    """
    if not isinstance(role_ids, list):
        raise InvalidError("role_ids must be a list of role UUIDs or names.")

    # Initialize Keycloak admin client
    keycloak_admin = KEYCLOAK_ADMIN_CLIENT()

    # Fetch the user representation
    user_rep = get_user(user_id)

    # Fetch and validate roles
    roles = []
    for role in role_ids:
        rep = get_role(role)
        roles.append(rep.get("name"))

    current_roles = keycloak_admin.get_realm_roles_of_user(user_rep.get("id"))
    current_role_names = get_user_roles(user_rep.get("id"))

    if roles is not None:
        if not roles:
            # No roles specified: Unassign all non-default roles
            roles_to_remove = [
                role for role in current_roles if role["name"] != "default-roles-master"
            ]
            if roles_to_remove:
                keycloak_admin.delete_realm_roles_of_user(
                    user_rep.get("id"), roles_to_remove
                )
                keycloak_admin.role
        else:
            # Unassign roles not in the request
            roles_to_remove = [
                role
                for role in current_roles
                if role["name"] not in roles and role["name"] != "default-roles-master"
            ]
            if roles_to_remove:
                keycloak_admin.delete_realm_roles_of_user(
                    user_rep.get("id"), roles_to_remove
                )

            # Assign new roles that are not already assigned
            available_realm_roles = keycloak_admin.get_realm_roles()
            roles_to_add = []
            for role in roles:
                if role not in current_role_names:
                    role_info = next(
                        (r for r in available_realm_roles if r["name"] == role),
                        None,
                    )
                    if role_info:
                        roles_to_add.append(role_info)
                    else:
                        raise NotFoundError(f"Role '{role}' not found in realm roles")

            if roles_to_add:
                keycloak_admin.assign_realm_roles(user_rep.get("id"), roles_to_add)

    user_rep = get_user(user_id)
    # We need to trigger the permissions sync for the registry.
    sync_registry_user(
        user_rep.get("username"),
        user_rep.get("id"),
        user_rep.get("email"),
        user_rep.get("roles"),
    )
    return user_rep


@raise_keycloak_error
def unassign_role_from_user(user_id, role_id):
    """
    Unassigns a realm role from a user.

    Args:
    - user_id: The UUID of the user or the username.
    - role_id: The UUID of the realm role or the name of it.

    Returns:
    - dict(): The updated user representation without the removed role.
    """

    # Fetch the user representation
    user_rep = get_user(user_id)
    user_roles = get_user_roles(user_rep.get("id"))

    role_rep = get_role(role_id)

    # Unassign the role if it is currently assigned to the user
    if role_rep["name"] in user_roles:
        KEYCLOAK_ADMIN_CLIENT().delete_realm_roles_of_user(user_rep["id"], [role_rep])

    user_rep = get_user(user_id)
    # We need to trigger the permissions sync for the registry.
    sync_registry_user(
        user_rep.get("username"),
        user_rep.get("id"),
        user_rep.get("email"),
        user_rep.get("roles"),
    )
    return user_rep


@raise_keycloak_error
def create_client_role(keycloak_admin, client_name, client_id, role_name):
    keycloak_admin.create_client_role(client_id, {"name": role_name}, skip_exists=True)
    return role_name


@raise_keycloak_error
def create_realm_role(keycloak_admin, role_name):
    config = current_app.config["settings"]
    realm_role = {
        "name": role_name,
        "composite": True,
        "clientRole": False,
        "containerId": config["REALM_NAME"],
    }
    keycloak_admin.create_realm_role(realm_role, skip_exists=True)

    return role_name


@raise_keycloak_error
def delete_realm_roles(keycloak_admin, roles_to_delete):
    # Delete the roles that are no longer needed
    for role in roles_to_delete:
        role_id = keycloak_admin.get_realm_role(role)["id"]
        keycloak_admin.delete_role_by_id(role_id)


@raise_keycloak_error
def delete_client_roles(keycloak_admin, client_roles_to_delete):
    for client_role in client_roles_to_delete:
        keycloak_admin.delete_client_role(
            keycloak_admin.get_client_id("minio"), client_role
        )


##################################
# this should be moved to another location....
##################################


def send_reset_password_email(to_email, rstoken, user_id, fullname):
    """
    Sends the reset password email to the specified email address with a subject and sender name.
    SMTP settings are fetched from Flask's app config.
    """
    config = current_app.config["settings"]  # Fetch SMTP settings from app config

    smtp_server = config["SMTP_SERVER"]
    smtp_port = config["SMTP_PORT"]
    sender_email = config["SMTP_EMAIL"]
    sender_password = config["SMTP_PASSWORD"]

    # Email subject and sender name
    subject = "Reset your STELAR account password"
    sender_name = "STELAR KLMS"

    # HTML message with headers for HTML content
    html_message = flask.render_template(
        "reset_password_email.html",
        fullname=fullname,
        rstoken=rstoken,
        user_id=user_id,
        main_ext_url=config["MAIN_EXT_URL"],
    )
    # Create the full email message with subject, MIME headers, and HTML content
    full_message = f"Subject: {subject}\nMIME-Version: 1.0\nContent-type: text/html\nFrom: {sender_name} <{sender_email}>\nTo: {to_email}\n\n{html_message}"
    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(smtp_server, int(smtp_port), context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, full_message)
    except Exception as e:
        # Log the error
        raise Exception(f"Error sending verification email: {str(e)}")
    except Exception as e:
        # Log the error
        raise Exception(f"Error sending verification email: {str(e)}")
