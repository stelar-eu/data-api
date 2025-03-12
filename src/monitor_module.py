import subprocess
from backend.minio import minio_fetch_policies

def get_current_realm_roles(keycloak_admin):
    # Get the list of existing realm roles from the system
    existing_realm_roles = keycloak_admin.get_realm_roles(True)
    existing_realm_roles_set = {role["name"] for role in existing_realm_roles}

    return existing_realm_roles_set


def get_current_policies():
    
    output_lines = minio_fetch_policies()

    return output_lines


def get_current_client_roles(keycloak_admin):
    existing_client_roles = keycloak_admin.get_client_roles(
        keycloak_admin.get_client_id("minio"), True
    )
    existing_client_roles_set = {role["name"] for role in existing_client_roles}

    return existing_client_roles_set
