from keycloak import KeycloakOpenID, KeycloakAdmin
from flask import current_app, session
import logging
import datetime



def initialize_keycloak_openid():
    config = current_app.config['settings']
    return KeycloakOpenID(
        server_url=config['KEYCLOAK_URL'],
        client_id=config['KEYCLOAK_CLIENT_ID'],
        realm_name=config['REALM_NAME'],
        client_secret_key=config['KEYCLOAK_CLIENT_SECRET'],
        verify=True
    )

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
    # config = current_app.config['settings']
    
    # Initialize Keycloak OpenID client
    # keycloak_openid = KeycloakOpenID(
    #     server_url=config['KEYCLOAK_URL'],
    #     client_id=config['KEYCLOAK_CLIENT_ID'],
    #     realm_name=config['REALM_NAME'],
    #     client_secret_key=config['KEYCLOAK_CLIENT_SECRET'],
    #     verify=True
    # )

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
    
    # Initialize Keycloak OpenID client
    # keycloak_openid = KeycloakOpenID(
    #     server_url=config['KEYCLOAK_URL'],
    #     client_id=config['KEYCLOAK_CLIENT_ID'],
    #     realm_name=config['REALM_NAME'],
    #     client_secret_key=config['KEYCLOAK_CLIENT_SECRET'],
    #     verify=True
    # )

    keycloak_openid = initialize_keycloak_openid()

    try:
        # Generate token by authenticating using username and password
        token = keycloak_openid.token(username, password)

        # Initialize KeycloakAdmin client with the new access token
        keycloak_admin = KeycloakAdmin(
            server_url=config['KEYCLOAK_URL'],
            realm_name=config['REALM_NAME'],
            token=token,  # Use the generated access token
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
