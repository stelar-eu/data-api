from keycloak import KeycloakOpenID, KeycloakAdmin, KeycloakAuthenticationError, KeycloakGetError
from flask import current_app, session
import logging
import datetime
import uuid
import re

logging.basicConfig(level=logging.DEBUG)


def is_valid_uuid(s):
    try:
        # Try converting the string to a UUID object
        uuid_obj = uuid.UUID(s)
        # Check if the string matches the canonical form of the UUID (with lowercase hexadecimal and hyphens)
        return str(uuid_obj) == s
    except ValueError:
        return False


def validate_email(email):
    """
    Validates an email address. Raises a ValueError if the email is invalid.

    :param email: The email address to validate (string).
    :raises ValueError: If the email is not a valid format.
    """
    # Regular expression for validating an email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_regex, email):
        raise ValueError(f"Invalid email address: {email}")

def email_username_unique(username, email):
    username_unique(username=username)
    email_unique(email=email)


def username_unique(username):
    keycloak_admin = init_admin_client_with_credentials()
    # Check for existing users with the same username
    existing_users = keycloak_admin.get_users({
        "username": username
    })

    if existing_users:
        raise ValueError(f"A user with the username '{username}' already exists.")
  

def email_unique(email):
    keycloak_admin = init_admin_client_with_credentials()

    # Check for existing users with the same email
    existing_emails = keycloak_admin.get_users({
        "email": email
    })
    if existing_emails:
        raise ValueError(f"A user with the email '{email}' already exists.")    


def initialize_keycloak_openid():
    config = current_app.config['settings']
    return KeycloakOpenID(
        server_url=config['KEYCLOAK_URL'],
        client_id=config['KEYCLOAK_CLIENT_ID'],
        realm_name=config['REALM_NAME'],
        client_secret_key=config['KEYCLOAK_CLIENT_SECRET'],
        verify=True
    )


def introspect_admin_token(access_token):
    """
    Introspects the given access token to check if it's valid and active.
    It also checks if the user has admin role.
    Returns True if the token is valid and admin, False if the token is invalid or expired or not admin.
    """
    try:
        keycloak_openid = initialize_keycloak_openid()
        introspect_response = keycloak_openid.introspect(access_token)
        
        # Check if the token is active and user has admin role
        if introspect_response.get("active", False):
            if(introspect_response.get("realm_access", False)):
                if ("admin" in introspect_response["realm_access"]["roles"]):
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
    except Exception as e:
        return False


def introspect_token(access_token):
    """
    Introspects the given access token to check if it's valid and active.
    Returns True if the token is valid, False if the token is invalid or expired.
    """
    try:
        keycloak_openid = initialize_keycloak_openid()
        introspect_response = keycloak_openid.introspect(access_token)
        # Check if the token is active
        if introspect_response.get("active", False):
            return True
        else:
            return False
    except Exception as e:
        return False

def refresh_access_token():
    """
    Refreshes the access token using the refresh token stored in the session.

    This function initializes the Keycloak OpenID client and uses the stored refresh token 
    to obtain a new access token. If successful, it updates the session with the new 
    access token and refresh token. In case of failure, it returns an appropriate error message.

    Returns:
        tuple: A tuple containing:
            - str or None: The refreshed access token if successful, otherwise None.
            - str or None: An error message if the refresh fails, otherwise None.

    Raises:
        Exception: If an error occurs during the token refresh process.
    """

    keycloak_openid = initialize_keycloak_openid()

    # Retrieve the refresh token from the session
    refresh_token = session.get('refresh_token')
    
    if not refresh_token:
        return None, 'Refresh token not found in session.'

    try:
        # Use the refresh token to get a new token set
        token = keycloak_openid.refresh_token(refresh_token)

        # Update the session with the new tokens
        session['access_token'] = token['access_token']
        session['refresh_token'] = token['refresh_token']

        return token['access_token'], None
    except Exception as e:
        # Handle errors during token refresh
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
    kopenid = initialize_keycloak_openid()
    try:
        token = kopenid.token(username, password)
        if token:
            return token
        else:
            return None
    except Exception as e:
        return None


def init_admin_client_with_credentials():
    """
    Initializes and returns a KeycloakAdmin client using the client service account. (If Enabled)

    Returns:
        KeycloakAdmin: An initialized KeycloakAdmin client

    """
    config = current_app.config['settings']
    
    try:
        # Initialize KeycloakAdmin client with the client service account
        keycloak_admin = KeycloakAdmin(
            server_url=config['KEYCLOAK_URL'],
            realm_name=config['REALM_NAME'],
            client_id=config['KEYCLOAK_CLIENT_ID'],
            client_secret_key=config['KEYCLOAK_CLIENT_SECRET'],
            verify=True
        )
        return keycloak_admin

    except Exception as e:
        raise RuntimeError(f'Failed to generate token and initialize KeycloakAdmin: {str(e)}')
    


def init_admin_client_with_admin_token(admin_token):
    """
    Initializes and returns a KeycloakAdmin client using a pre-obtained admin token.

    Args:
        admin_token: An OAuth2.0 admin token

    Returns:
        KeycloakAdmin: An initialized KeycloakAdmin client with admin token.
    
    Raises:
        RuntimeError: If initialization fails due to an error.
    """
    config = current_app.config['settings']
    

    
    try:
        
        # Initialize KeycloakAdmin using the token
        admin_client = KeycloakAdmin(
            server_url=config['KEYCLOAK_URL'],
            realm_name=config['REALM_NAME'],
            client_id=config['KEYCLOAK_CLIENT_ID'],
            verify=True,
            token=admin_token
        )
        
        return admin_client
    except Exception as e:
        raise RuntimeError(f'Failed to initialize KeycloakAdmin with admin token: {str(e)}')



def init_admin_client(username, password):
    """
    Initializes and returns a KeycloakAdmin client using the admin username and password.
    
    This function authenticates an admin user using their username and password to obtain a new
    access token. It then uses this access token to initialize a KeycloakAdmin client. The access 
    token is not stored in the session in this case, since it is generated dynamically for each 
    login request.

    Args:
        username (str): The username of the admin user.
        password (str): The password of the admin user.

    Returns:
        KeycloakAdmin: An initialized KeycloakAdmin client with a valid access token.

    Raises:
        ValueError: If the username or password is invalid or the authentication fails.
        RuntimeError: If the token generation or client initialization fails.
    """
    config = current_app.config['settings']

    keycloak_openid = initialize_keycloak_openid()

    try:
        # Generate token by authenticating using username and password
        token = keycloak_openid.token(username, password)

        # Initialize KeycloakAdmin client with the new access token
        keycloak_admin = KeycloakAdmin(
            server_url=config['KEYCLOAK_URL'],
            realm_name=config['REALM_NAME'],
            token=token,  
            verify=True
        )

        return keycloak_admin

    except Exception as e:
        raise RuntimeError(f'Failed to generate token and initialize KeycloakAdmin: {str(e)}')



def get_user_roles(user_id, keycloak_admin):
    """
    Fetches the roles assigned to a user with the given user_id using KeycloakAdmin object.

    :param user_id: The ID of the user whose roles are to be fetched.
    :param keycloak_admin: The KeycloakAdmin object to interact with Keycloak.
    :return: A list of roles assigned to the user.
    """
    try:
        # Get the roles assigned to the user from the realm
        realm_roles = keycloak_admin.get_realm_roles_of_user(user_id)

        # Combining both realm and client roles
        assigned_roles = []

        # Adding realm roles
        if realm_roles:
            for role in realm_roles:
                assigned_roles.append(role['name'])
                

        return assigned_roles

    except Exception as e:
        print(f"Error fetching roles for user {user_id}: {str(e)}")
        return []

def create_user_with_password(
    username,
    email,
    first_name,
    last_name,
    password,
    enabled=True,
    temporary_password=False,
    attributes=None
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
    :return: The ID of the created user, or None if creation failed

    Raises:
    - ValueError if the username or the email are not unique

    """
    try:
        # Initialize the Keycloak admin client
        keycloak_admin = init_admin_client_with_credentials()

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
            "emailVerified": True,
            "attributes": attributes or {}
        }

        user_id = keycloak_admin.create_user(payload=user_payload, exist_ok=False)

        if user_id:
            keycloak_admin.set_user_password(user_id=user_id, password=password, temporary=temporary_password)
        
        return user_id
    except KeycloakAuthenticationError as e:
        logging.error(f"Error updating user: {e}")
        return None
    except ValueError as ve:
        raise ValueError(ve)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return None


def update_user(
        user_id, 
        username=None, 
        first_name=None, 
        last_name=None, 
        email=None, 
        enabled=None):
    """
    Updates a user in the Keycloak realm by the given user ID.
    
    Parameters:
    - username (str, optional): The new username for the user.
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
        keycloak_admin = init_admin_client_with_credentials()
       
        # Prepare the update data dictionary with only the fields that are not None
        user_data = {}

        if username:
            # Will raise ValueError if username not unique
            username_unique(username=username)
            user_data['username'] = username
        if first_name:
            user_data['firstName'] = first_name
        if last_name:
            user_data['lastName'] = last_name
        if email:
            # Validate that an email matches the RegEx
            validate_email(email=email)
            # Will raise ValueError if email not unique
            email_unique(email=email)
            user_data['email'] = email  
        if enabled is not None:
            user_data['enabled'] = enabled
    
        # Support both selecting user by UUID and by Username
        if not is_valid_uuid(user_id):
            user_id = keycloak_admin.get_user_id(user_id)

        keycloak_admin.update_user(user_id, user_data)

        updated_user_json = get_user(user_id=user_id)
        
        return updated_user_json
    
    except KeycloakAuthenticationError as e:
        logging.error(f"Error updating user: {e}")
        return None
    except ValueError as ve:
        raise ValueError(ve)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return None


def get_user(user_id=None):
    """
    Retrieve a user from Keycloak by user ID.

    :param user_id: The ID of the user to retrieve (str). If None, returns None.
    :return: A dictionary representation of the user if found, otherwise None.
    """
    if not user_id or not isinstance(user_id, str):
        return None
    
    try:
        keycloak_admin = init_admin_client_with_credentials()

        #Support both searching by UUID and by Username
        if is_valid_uuid(user_id):
            user_representation = keycloak_admin.get_user(user_id)
        else:
            id= keycloak_admin.get_user_id(user_id)
            user_representation= keycloak_admin.get_user(id)

        if user_representation:
            # Clean up unnecessary fields (if present) to make response cleaner
            for field in ['disableableCredentialTypes', 'access', 'notBefore', 'requiredActions', 'totp']:
                user_representation.pop(field, None)
            return user_representation
        return None
    
    except Exception as e:
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
        keycloak_admin = init_admin_client_with_credentials()

        #Support both searching by UUID and by Username
        if not is_valid_uuid(user_id):
            id = keycloak_admin.get_user_id(user_id)
            user_id = keycloak_admin.get_user(id)

        keycloak_admin.delete_user(user_id['id'])
        return user_id['id']

    except KeycloakGetError as e:
        if e.response_code == 404:
            raise AttributeError(f"User with ID '{user_id}' not found.") from e
        else:
            logging.error(f"Unexpected Keycloak error: {e}")
            raise

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise



def get_users_from_keycloak(access_token, offset, limit):
    """
    Retrieves a list of users from Keycloak with pagination and additional user details.

    Args:
        access_token: An admin related OAuth2.0 token
        offset (int): The starting index for the users to retrieve (default is 0).
        limit (int): The maximum number of users to retrieve (default is 50).

    Returns:
        A list of user dictionaries containing user details.
    
    Raises:
        ValueError: If invalid values for offset or limit are provided.
        RuntimeError: If there is an issue with the Keycloak connection or API interaction.
    """
    try:
        # Initialize KeycloakAdmin client with credentials
        keycloak_admin = init_admin_client_with_credentials()

        # Validate and adjust pagination values
        if limit < 0 or offset < 0:
            raise ValueError("Limit and offset must be greater than 0.")
        
        if limit == 0:
            query={"first": offset}
        else:
            query={"first": offset, "max": limit}


        users = keycloak_admin.get_users(query=query)

        result = []
        for user in users:
            created_timestamp = user.get('createdTimestamp')
            creation_date = None
            if created_timestamp:
                creation_date = datetime.datetime.fromtimestamp(created_timestamp / 1000.0).strftime('%d-%m-%Y')

            # Get roles and exclude 'default-roles-master'
            roles = get_user_roles(user.get("id"), keycloak_admin)
            filtered_roles = [role for role in roles if role != 'default-roles-master']
            
            active_status = user.get('enabled', False)
            user_info = {
                "username": user.get("username"),
                "email": user.get("email"),
                "fullname": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                "joined_date": creation_date,
                "user_id": user.get("id"),
                "roles": filtered_roles,
                "active": active_status  
            }
            result.append(user_info)
        
        return result

    except ValueError as ve:
        logging.debug(str(ve))
        raise ValueError(f"Invalid parameter: {str(ve)}")
    except RuntimeError as re:
        logging.debug(str(re))
        raise RuntimeError(f"Failed to fetch users from Keycloak: {str(re)}")



def fetch_user_creation_date(user_id):
    """
    Fetches user creation date from Keycloak Admin API using client credentials access token.

    """    

    keycloak_admin = init_admin_client_with_credentials()

    try:
        user = keycloak_admin.get_user(user_id)
        created_timestamp = user.get('createdTimestamp')
        if created_timestamp:
            creation_date = datetime.datetime.fromtimestamp(created_timestamp / 1000.0).strftime('%d-%m-%Y')
            return creation_date
        return None
    except Exception as e:
        logging.error(f"Error fetching user creation date: {e}")
        return None
    


def create_client_role(keycloak_admin, client_name, client_id, role_name):
    print(client_id)
    keycloak_admin.create_client_role(client_id, {'name': role_name},skip_exists=True)
    print(f'Role "{role_name}" created successfully for client "{client_name}".')
    return role_name



def create_realm_role(keycloak_admin, role_name):
    config = current_app.config['settings']
    realm_role = {
        "name": role_name,
        "composite": True,
        "clientRole": False,
        "containerId": config['REALM_NAME']
    }
    keycloak_admin.create_realm_role(realm_role,skip_exists=True)

    return role_name



def delete_realm_roles(keycloak_admin,roles_to_delete):
# Delete the roles that are no longer needed
    for role in roles_to_delete:
        print("realm role to delete: ",role)
        role_id = keycloak_admin.get_realm_role(role)["id"]
        keycloak_admin.delete_role_by_id(role_id)



def delete_client_roles(keycloak_admin,client_roles_to_delete):
    for client_role in client_roles_to_delete:
        keycloak_admin.delete_client_role(keycloak_admin.get_client_id('minio'),client_role)
