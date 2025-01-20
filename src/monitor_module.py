import subprocess


def get_current_realm_roles(keycloak_admin):
    # Get the list of existing realm roles from the system
    existing_realm_roles = keycloak_admin.get_realm_roles(True)
    existing_realm_roles_set = {role["name"] for role in existing_realm_roles}

    return existing_realm_roles_set


def get_current_policies():
    command = "mc admin policy ls myminio"

    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
    )

    # Check if the command was successful
    if result.returncode != 0:
        print(f"Error running command: {result.stderr}")
        return set()

    # Split the output into lines or words (depending on the expected output format)
    output_lines = result.stdout.splitlines()

    return output_lines


def get_current_client_roles(keycloak_admin):
    existing_client_roles = keycloak_admin.get_client_roles(
        keycloak_admin.get_client_id("minio"), True
    )
    existing_client_roles_set = {role["name"] for role in existing_client_roles}

    return existing_client_roles_set
