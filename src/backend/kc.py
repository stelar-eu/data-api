from keycloak.openid_connection import KeycloakOpenIDConnection, KeycloakOpenID
from keycloak.keycloak_admin import KeycloakAdmin
from flask import current_app


# Init global client to the Keycloak Server, to avoid bottlenecks imposed by previously
# instantly established clients on request arrival.
class KeycloakClientSingleton:
    """Singleton class to hold a global Keycloak Connection and Client."""

    _admin = None
    _connection = None
    _openid = None

    @classmethod
    def get_admin(cls):
        """Ensure the instance is initialized inside an app context."""
        if cls._admin or cls._connection or cls._openid is None:
            cls._initialize_keycloak()
        return cls._admin

    @classmethod
    def get_openid(cls):
        """Ensure the instance is initialized inside an app context."""
        if cls._admin or cls._connection or cls._openid is None:
            cls._initialize_keycloak()
        return cls._openid

    @classmethod
    def _initialize_keycloak(cls):
        """Create Keycloak connection within the correct Flask context."""
        app = current_app._get_current_object()
        with app.app_context():  # Ensures app context is active
            config = app.config["settings"]
            cls._connection = KeycloakOpenIDConnection(
                server_url=config["KEYCLOAK_URL"],
                realm_name=config["REALM_NAME"],
                client_id=config["KEYCLOAK_CLIENT_ID"],
                client_secret_key=config["KEYCLOAK_CLIENT_SECRET"],
                verify=True,
            )
            cls._admin = KeycloakAdmin(connection=cls._connection)
            cls._openid = KeycloakOpenID(
                server_url=config["KEYCLOAK_URL"],
                realm_name=config["REALM_NAME"],
                client_id=config["KEYCLOAK_CLIENT_ID"],
                client_secret_key=config["KEYCLOAK_CLIENT_SECRET"],
                verify=True,
            )


# The keycloak clients singletons
KEYCLOAK_OPENID_CLIENT = KeycloakClientSingleton.get_openid
KEYCLOAK_ADMIN_CLIENT = KeycloakClientSingleton.get_admin
