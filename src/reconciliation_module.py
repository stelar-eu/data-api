import hashlib
import os

default_minio_policies = {
    "consoleAdmin",
    "diagnostics",
    "readonly",
    "readwrite",
    "writeonly",
}
default_keycloak_roles = {
    "default-roles-master",
    "admin",
    "offline_access",
    "create-realm",
    "uma_authorization",
}
default_client_roles = {"consoleAdmin"}


def generate_random_hash() -> str:
    # Generate 32 random bytes
    random_bytes = os.urandom(32)

    # Create a SHA-256 hash object
    hash_object = hashlib.sha256(random_bytes)

    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()

    return hash_hex


def update_roles_from_yaml(roles_list, existing_realm_roles):

    # Get the list of roles from the updated YAML file
    updated_roles = {role["name"] for role in roles_list}
    # print(updated_roles)

    # print(existing_roles_set)

    # Find roles that need to be deleted
    roles_to_delete = (existing_realm_roles - default_keycloak_roles) - updated_roles

    return roles_to_delete


def update_policies_from_yaml(roles_list, existing_policies):
    policy_names_set = set()
    for role in roles_list:
        for perm in role["permissions"]:
            hashed_policy_name = generate_random_hash()
            policy_names_set.update({hashed_policy_name})

    # Create a set from the output lines
    policies_to_delete = (
        set(existing_policies) - default_minio_policies
    ) - policy_names_set

    print("policies to delete: ", policies_to_delete)

    return policies_to_delete, policy_names_set


def update_client_roles(policy_names_set, exisitng_client_roles):

    client_roles_to_delete = (
        exisitng_client_roles - default_client_roles
    ) - policy_names_set

    print("client roles deleted: ", client_roles_to_delete)

    return client_roles_to_delete
