import pytest

def test_update_roles_from_yaml():
    from reconciliation_module import update_roles_from_yaml
    ########################################################
    # 1st case: we have 3 roles in the yaml file and 4 roles in the realm
    # 1 role in the realm is not in the yaml file
    # we should delete that role

    roles_list = [
        {"name": "role1"},
        {"name": "role2"},
        {"name": "role3"},
    ]
    existing_realm_roles = {
        "role1",
        "role2",
        "role3",
        "role4"
    }

    roles_to_delete = update_roles_from_yaml(roles_list, existing_realm_roles)
    assert roles_to_delete == {
        "role4"
    }

    ########################################################
    # 2nd case: we have 3 roles in the yaml file and 3 roles in the realm
    # all roles in the realm are in the yaml file
    # we should not delete any role

    roles_list = [
        {"name": "role1"},
        {"name": "role2"},
        {"name": "role3"},
    ]
    existing_realm_roles = {
        "role1",
        "role2",
        "role3"
    }

    roles_to_delete = update_roles_from_yaml(roles_list, existing_realm_roles)
    assert roles_to_delete == set()

    ########################################################
    # 3rd case: we have 1 role in the yaml file and 3 roles in the realm
    # 2 roles in the realm are not in the yaml file
    # we should delete those 2 roles

    roles_list = [
        {"name": "role1"},
    ]
    existing_realm_roles = {
        "role1",
        "role2",
        "role3"
    }

    roles_to_delete = update_roles_from_yaml(roles_list, existing_realm_roles)
    assert roles_to_delete == {
        "role2",
        "role3"
    }

    ########################################################
    # 4th case: we have 3 roles in the yaml file and 0 roles in the realm
    # we should not delete any role

    roles_list = [
        {"name": "role1"},
        {"name": "role2"},
        {"name": "role3"},
    ]
    existing_realm_roles = set()

    roles_to_delete = update_roles_from_yaml(roles_list, existing_realm_roles)
    assert roles_to_delete == set()

    ########################################################
    # 5th case: we have 3 roles in the yaml file and 7 roles in the realm
    # 4 roles in the realm are not in the yaml file
    # we should delete only those 4 roles
    # we should not delete the default roles

    roles_list = [
        {"name": "role1"},
        {"name": "role2"},
        {"name": "role3"},
    ]
    existing_realm_roles = {
        "role1",
        "role2",
        "role3",
        "role4",
        "default-roles-master",
        "admin",
        "offline_access",
        "create-realm",
        "uma_authorization",
        "puller",
        "pusher"
    }

    roles_to_delete = update_roles_from_yaml(roles_list, existing_realm_roles)
    assert roles_to_delete == {
        "role4"
    }
    assert not roles_to_delete == {
        "default-roles-master",
        "admin",
        "offline_access",
        "create-realm",
        "uma_authorization"
    }

def test_policies_from_yaml():
    from reconciliation_module import update_policies_from_yaml
    ########################################################
    # 1st case: we have 3 policies in the yaml file and 4 policies in the minio server
    # 1 policy in the minio server is not in the yaml file
    # we should delete that policy

    roles_list = [
        "policyfile1",
        "policyfile2",
        "policyfile3",
    ]
    existing_policies = {
        "policyfile1",
        "policyfile2",
        "policyfile3",
        "policyfile4"
    }

    policies_to_delete, policy_names_set = update_policies_from_yaml(roles_list, existing_policies)
    assert policies_to_delete == {
        "policyfile4"
    }
    assert policy_names_set == {
        "policyfile1",
        "policyfile2",
        "policyfile3"
    }

    ########################################################
    # 2nd case: we have 3 policies in the yaml file and 3 policies in the minio server
    # all policies in the minio server are in the yaml file
    # we should not delete any policy

    roles_list = [
        "policyfile1",
        "policyfile2",
        "policyfile3",
    ]
    existing_policies = {
        "policyfile1",
        "policyfile2",
        "policyfile3"
    }

    policies_to_delete, policy_names_set = update_policies_from_yaml(roles_list, existing_policies)
    assert policies_to_delete == set()
    assert policy_names_set == {
        "policyfile1",
        "policyfile2",
        "policyfile3"
    }

    ########################################################
    # 3rd case: we have 1 policy in the yaml file and 3 policies in the minio server
    # 2 policies in the minio server are not in the yaml file
    # we should delete those 2 policies

    roles_list = [
        "policyfile1",
    ]
    existing_policies = {
        "policyfile1",
        "policyfile2",
        "policyfile3"
    }

    policies_to_delete, policy_names_set = update_policies_from_yaml(roles_list, existing_policies)
    assert policies_to_delete == {
        "policyfile2",
        "policyfile3"
    }
    assert policy_names_set == {
        "policyfile1"
    }

    ########################################################
    # 4th case: we have 3 policies in the yaml file and 0 policies in the minio server
    # we should not delete any policy

    roles_list = [
        "policyfile1",
        "policyfile2",
        "policyfile3",
    ]
    existing_policies = set()

    policies_to_delete, policy_names_set = update_policies_from_yaml(roles_list, existing_policies)
    assert policies_to_delete == set()
    assert policy_names_set == {
        "policyfile1",
        "policyfile2",
        "policyfile3"
    }

    ########################################################
    # 5th case: we have 3 policies in the yaml file and 8 policies in the minio server
    # 1 policy in the minio server is not in the yaml file
    # we should delete only those 5 policies
    # we should not delete the default policies

    roles_list = [
        "policyfile1",
        "policyfile2",
        "policyfile3",
    ]
    existing_policies = {
        "policyfile1",
        "policyfile2",
        "policyfile3",
        "policyfile4",
        "consoleAdmin",
        "diagnostics",
        "readonly",
        "readwrite",
        "writeonly",
    }

    policies_to_delete, policy_names_set = update_policies_from_yaml(roles_list, existing_policies)
    assert policies_to_delete == {
        "policyfile4"
    }
    assert policy_names_set == {
        "policyfile1",
        "policyfile2",
        "policyfile3",
    }
    assert not policies_to_delete == {
        "consoleAdmin",
        "diagnostics",
        "readonly",
        "readwrite",
        "writeonly",
    }

def test_update_client_roles():
    from reconciliation_module import update_client_roles
    ########################################################
    # 1st case: we have 3 policies in the yaml file and 4 client roles in the minio server
    # 1 client role in the minio server is not in the yaml file
    # we should delete that client role

    policy_names_set = {
        "client_role1",
        "client_role2",
        "client_role3",
    }
    exisitng_client_roles = {
        "client_role1",
        "client_role2",
        "client_role3",
        "client_role4"
    }

    client_roles_to_delete = update_client_roles(policy_names_set, exisitng_client_roles)
    assert client_roles_to_delete == {
        "client_role4"
    }

    ########################################################
    # 2nd case: we have 3 policies in the yaml file and 3 client roles in the minio server
    # all client roles in the minio server are in the yaml file
    # we should not delete any client role

    policy_names_set = {
        "client_role1",
        "client_role2",
        "client_role3",
    }
    exisitng_client_roles = {
        "client_role1",
        "client_role2",
        "client_role3"
    }

    client_roles_to_delete = update_client_roles(policy_names_set, exisitng_client_roles)
    assert client_roles_to_delete == set()

    ########################################################
    # 3rd case: we have 1 policy in the yaml file and 3 client roles in the minio server
    # 2 client roles in the minio server are not in the yaml file
    # we should delete those 2 client roles

    policy_names_set = {
        "client_role1",
    }
    exisitng_client_roles = {
        "client_role1",
        "client_role2",
        "client_role3"
    }

    client_roles_to_delete = update_client_roles(policy_names_set, exisitng_client_roles)
    assert client_roles_to_delete == {
        "client_role2",
        "client_role3"
    }

    ########################################################
    # 4th case: we have 3 policies in the yaml file and 0 client roles in the minio server
    # we should not delete any client role

    policy_names_set = {
        "client_role1",
        "client_role2",
        "client_role3",
    }
    exisitng_client_roles = set()

    client_roles_to_delete = update_client_roles(policy_names_set, exisitng_client_roles)
    assert client_roles_to_delete == set()

    ########################################################
    # 5th case: we have 3 policies in the yaml file and 7 client roles in the minio server
    # 4 client roles in the minio server are not in the yaml file
    # we should delete only those 4 client roles
    # we should not delete the default client roles

    policy_names_set = {
        "client_role1",
        "client_role2",
        "client_role3",
    }
    exisitng_client_roles = {
        "client_role1",
        "client_role2",
        "client_role3",
        "client_role4",
        "consoleAdmin"
    }

    client_roles_to_delete = update_client_roles(policy_names_set, exisitng_client_roles)
    assert client_roles_to_delete == {
        "client_role4"
    }
    assert not client_roles_to_delete == {
        "consoleAdmin"
    }
    assert not client_roles_to_delete == {
        "client_role1",
        "client_role2",
        "client_role3"
    }
   