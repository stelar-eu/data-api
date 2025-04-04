import base64
import datetime
import logging
import smtplib
import ssl
from io import BytesIO

import flask
import jwt
import pyotp
import qrcode
from flask import current_app, session, url_for
from keycloak import (
    KeycloakAuthenticationError,
    KeycloakGetError,
)
import sql_utils
from backend.ckan import ckan_request
from backend.pgsql import execSql
from backend.kc import KEYCLOAK_ADMIN_CLIENT, KEYCLOAK_OPENID_CLIENT

from exceptions import APIException, AuthenticationError, AuthorizationError, BackendError, InternalException, InvalidError
from utils import is_valid_uuid, validate_email

logger = logging.getLogger(__name__)


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


def username_unique(username):
    # Check for existing users with the same username
    existing_users = KEYCLOAK_ADMIN_CLIENT().get_users({"username": username})

    if existing_users:
        raise InvalidError(f"A user with the username '{username}' already exists.")


def email_unique(email):
    # Check for existing users with the same email
    existing_emails = KEYCLOAK_ADMIN_CLIENT().get_users({"email": email})
    if existing_emails:
        raise InvalidError(f"A user with the email '{email}' already exists.")


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



def introspect_admin_token(access_token):
    """
    Introspects the given access token to check if it's valid, active,
    and if the user has the admin role.
    Returns True if the token is valid and admin.
    Raises TokenExpiredError if the token is inactive/expired.
    Raises AuthorizationError if the token is active but not for an admin user.
    """
    
    # keycloak_openid = initialize_keycloak_openid()
    # introspect_response = keycloak_openid.introspect(access_token)
    introspect_response = introspect_token(access_token)

    # # Check if the token is active
    # if not introspect_response.get("active", False):
    #     raise AuthenticationError(message="Token expired")
    
    # Optionally check for realm_access if needed
    if not introspect_response.get("realm_access", False):
        # You can decide how to handle this; here we treat it as a token issue.
        raise APIException(
            401,
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
            raise AttributeError(f"Failed to generate 2FA token: {str(e)}")
    else:
        raise ValueError("Not valid UUID")


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


def disable_2fa(user_id):
    if is_valid_uuid(user_id):
        if sql_utils.two_factor_revoke(user_id=user_id):
            return True
    else:
        raise ValueError("Not valid UUID")


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

    Raises:
        Exception: If an error occurs during the token refresh process.
    """

    if not refresh_token:
        return None

    try:
        token = KEYCLOAK_OPENID_CLIENT().refresh_token(
            refresh_token, grant_type="refresh_token"
        )
        return token
    except Exception as e:
        return None, str(e)


def get_token(username, password):
    """
    Returns a token for a user in Keycloak by using username and password.

    Args:
        username: The username of the user in Keycloak
        password The secret password of the user in Keycloak

    Returns:
        str: The access_token
        null: Error return

    """
    try:
        token = KEYCLOAK_OPENID_CLIENT().token(username, password)
        if token:
            return token
        else:
            return None
    except Exception as e:
        logger.debug("Error while getting token: %s", str(e), exc_info=True)
        return None


def get_user_roles(user_id):
    """
    Fetches the roles assigned to a user with the given user_id using KeycloakAdmin object.

    :param user_id: The ID of the user whose roles are to be fetched.
    :return: A list of roles assigned to the user.
    """
    try:
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

    except Exception as e:
        return []


def get_role(role_id):
    """
    Fetches the role by ID from the Realm

    :param user_id: The ID or the name of the role to be fetched.
    :return: The role representation
    """
    try:
        if is_valid_uuid(role_id):
            role_rep = KEYCLOAK_ADMIN_CLIENT().get_realm_role_by_id(role_id)
        else:
            role_rep = KEYCLOAK_ADMIN_CLIENT().get_realm_role(role_id)

        if not role_rep:
            return None

        return role_rep

    except Exception as e:
        return None


def get_realm_roles():
    """
    Returns the realm roles exluding the Keycloak default roles.
    """

    try:
        roles = KEYCLOAK_ADMIN_CLIENT().get_realm_roles(brief_representation=True)

        # Define a set of roles to exclude
        roles_to_exclude = {
            "offline_access",
            "uma_authorization",
            "create-realm",
            "default-roles-master",
        }

        # Filter the roles, excluding those in the roles_to_exclude set
        filtered_roles = [
            role for role in roles if role["name"] not in roles_to_exclude
        ]

        return filtered_roles

    except Exception as e:
        raise Exception(str(e))


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

    Raises:
    - ValueError if the username or the email are not unique

    """
    try:
        # Initialize the Keycloak admin client
        keycloak_admin = KEYCLOAK_ADMIN_CLIENT()

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

        user_id = keycloak_admin.create_user(payload=user_payload, exist_ok=False)

        if user_id:
            keycloak_admin.set_user_password(
                user_id=user_id, password=password, temporary=temporary_password
            )

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
        except Exception as e:
            logger.error("Error while calling ckan_request: %s", str(e), exc_info=True)
            keycloak_admin.delete_user(user_id)
            raise BackendError("Error while creating user") from e

        query = 'UPDATE public."user" SET sysadmin = %s WHERE id = %s'
        execSql(query, (True, user_id))

        return user_id
    except KeycloakAuthenticationError as e:
        raise InternalException("Keycloak authentication error") from e


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
    try:
        # Prepare the update data dictionary with only the fields that are not None
        user_data = {}
        user_repr = get_user(user_id=user_id)

        if user_repr["username"] == "admin":
            return {"warning": "Modifications to administrator account are not allowed"}

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

    except KeycloakAuthenticationError as e:
        raise InternalException("Keycloak authentication error") from e


def get_user(user_id=None):
    """
    Retrieve a user from Keycloak by user ID.
    It also returns the roles

    :param user_id: The ID of the user to retrieve (str). If None, returns None.
    :return: A dictionary representation of the user if found, otherwise None.
    """
    if not user_id or not isinstance(user_id, str):
        return None

    try:
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

    except Exception as e:
        logger.debug("Error while getting user: %s", str(e), exc_info=True)
        return None


def delete_user(user_id=None):
    """
    Delete a user from Keycloak by user UUID.

    :param user_id: The UUID of the user to delete (str). If None, returns None.
    :return: The UUID of the deleted user.
    :raises AttributeError: If the user is not found.

    """
    if not user_id or not isinstance(user_id, str):
        return None

    try:
        # Support both UUID andsername
        if not is_valid_uuid(user_id):
            id = KEYCLOAK_ADMIN_CLIENT().get_user_id(user_id)
            user_id = KEYCLOAK_ADMIN_CLIENT().get_user(id)["id"]

        KEYCLOAK_ADMIN_CLIENT().delete_user(user_id)
        return user_id

    except KeycloakGetError as e:
        if e.response_code == 404:
            raise AttributeError(f"User with ID '{user_id}' not found.") from e
        else:
            raise

    except Exception as e:
        raise


def get_users_from_keycloak(offset, limit):
    """
    Retrieves a list of users from Keycloak with pagination and additional user details.

    Args:
        offset (int): The starting index for the users to retrieve (default is 0).
        limit (int): The maximum number of users to retrieve (default is 50).

    Returns:
        A list of user dictionaries containing user details.

    Raises:
        ValueError: If invalid values for offset or limit are provided.
        RuntimeError: If there is an issue with the Keycloak connection or API interaction.
    """
    try:
        # Validate and adjust pagination values
        if limit < 0 or offset < 0:
            raise ValueError("Limit and offset must be greater than 0.")

        if limit == 0:
            query = {"first": offset}
        else:
            query = {"first": offset, "max": limit}

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

    except ValueError as ve:
        raise ValueError(f"Invalid parameter: {str(ve)}")
    except RuntimeError as re:
        raise RuntimeError(f"Failed to fetch users from Keycloak: {str(re)}")


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


def assign_role_to_user(user_id, role_id):
    """
    Assigns realm role to user.

    Args:
    - user_id: The UUID of the user or the username.
    - role_id: The UUID of the realm role or the name of it.

    Returns:
    - dict(): The updated user represantation containing the new role
    """

    try:
        # Fetch the user representation
        user_rep = get_user(user_id)

        if not user_rep:
            raise ValueError(f"User with ID: {user_id} was not found.")

        user_roles = get_user_roles(user_rep.get("id"))

        role_rep = get_role(role_id)
        if not role_rep:
            raise ValueError(f"Role with ID: {role_id} was not found")

        # Assign the role to the user if it is not already assigned
        if role_rep["name"] not in user_roles:
            KEYCLOAK_ADMIN_CLIENT().assign_realm_roles(user_rep["id"], [role_rep])
            return get_user(user_id)
        else:
            raise AttributeError(
                f"Role with ID: {role_id} already assigned to user with ID: {user_id}"
            )

    except ValueError as ve:
        raise ValueError(str(ve))
    except AttributeError as ae:
        raise AttributeError(str(ae))
    except Exception as e:
        pass


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
        raise ValueError("role_ids must be a list of role UUIDs or names.")

    try:

        # Fetch the user representation
        user_rep = get_user(user_id)
        if not user_rep:
            raise ValueError(f"User with ID: {user_id} was not found.")

        user_roles = get_user_roles(user_rep.get("id"))

        # Fetch all roles representations
        roles_to_assign = []
        already_assigned_roles = []
        for role_id in role_ids:
            role_rep = get_role(role_id)
            if not role_rep:
                raise ValueError(f"Role with ID: {role_id} was not found.")

            # Check if the role is already assigned
            if role_rep["name"] not in user_roles:
                roles_to_assign.append(role_rep)
            else:
                already_assigned_roles.append(role_rep["name"])

        # Assign roles to the user if there are new roles to assign
        if roles_to_assign:
            KEYCLOAK_ADMIN_CLIENT().assign_realm_roles(user_rep["id"], roles_to_assign)

        return get_user(user_id)

    except ValueError as ve:
        raise
    except AttributeError as ae:
        raise
    except Exception as e:
        raise


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
        raise ValueError("role_ids must be a list of role UUIDs or names.")

    try:
        # Initialize Keycloak admin client
        keycloak_admin = KEYCLOAK_ADMIN_CLIENT()

        # Fetch the user representation
        user_rep = get_user(user_id)
        if not user_rep:
            raise ValueError(f"User with ID: {user_id} was not found.")

        # Fetch and validate roles
        roles = []
        for role in role_ids:
            rep = get_role(role)
            if rep is None:
                raise ValueError(f"The following role was not found: {role}")
            else:
                roles.append(rep.get("name"))

        current_roles = keycloak_admin.get_realm_roles_of_user(user_rep.get("id"))
        current_role_names = get_user_roles(user_rep.get("id"))

        if roles is not None:
            if not roles:
                # No roles specified: Unassign all non-default roles
                roles_to_remove = [
                    role
                    for role in current_roles
                    if role["name"] != "default-roles-master"
                ]
                if roles_to_remove:
                    keycloak_admin.delete_realm_roles_of_user(
                        user_rep.get("id"), roles_to_remove
                    )
            else:
                # Unassign roles not in the request
                roles_to_remove = [
                    role
                    for role in current_roles
                    if role["name"] not in roles
                    and role["name"] != "default-roles-master"
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
                            raise ValueError(f"Role '{role}' not found in realm roles")

                if roles_to_add:
                    keycloak_admin.assign_realm_roles(user_rep.get("id"), roles_to_add)

        return get_user(user_id)

    except ValueError as ve:
        raise
    except AttributeError as ae:
        raise
    except Exception as e:
        raise


def unassign_role_from_user(user_id, role_id):
    """
    Unassigns a realm role from a user.

    Args:
    - user_id: The UUID of the user or the username.
    - role_id: The UUID of the realm role or the name of it.

    Returns:
    - dict(): The updated user representation without the removed role.
    """
    try:
        # Fetch the user representation
        user_rep = get_user(user_id)
        if not user_rep:
            raise ValueError(f"User with ID: {user_id} was not found.")

        user_roles = get_user_roles(user_rep.get("id"))

        role_rep = get_role(role_id)
        if not role_rep:
            raise ValueError(f"Role with ID: {role_id} was not found.")

        # Unassign the role if it is currently assigned to the user
        if role_rep["name"] in user_roles:
            KEYCLOAK_ADMIN_CLIENT().delete_realm_roles_of_user(
                user_rep["id"], [role_rep]
            )
            return get_user(user_id)
        else:
            raise AttributeError(
                f"Role with ID: {role_id} is not assigned to user with ID: {user_id}"
            )

    except ValueError as ve:
        raise ValueError(str(ve))
    except AttributeError as ae:
        raise AttributeError(str(ae))
    except Exception as e:
        pass


def create_client_role(keycloak_admin, client_name, client_id, role_name):
    print(client_id)
    keycloak_admin.create_client_role(client_id, {"name": role_name}, skip_exists=True)
    print(f'Role "{role_name}" created successfully for client "{client_name}".')
    return role_name


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


def delete_realm_roles(keycloak_admin, roles_to_delete):
    # Delete the roles that are no longer needed
    for role in roles_to_delete:
        print("realm role to delete: ", role)
        role_id = keycloak_admin.get_realm_role(role)["id"]
        keycloak_admin.delete_role_by_id(role_id)


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

    # Plain text message without headers (headers will be handled separately)
    plain_message = f"""\
Dear {fullname},

Follow this link to reset your password: 

{config['MAIN_EXT_URL']}{url_for('dashboard_blueprint.reset_password', rs_token=rstoken, user_id=user_id)}

The link will be valid for the next 30 minutes.

If you didn't request a password reset, consider changing your password and enabling 2FA for your account.

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
    except Exception as e:
        # Log the error
        raise Exception(f"Error sending verification email: {str(e)}")
