import pytest
import json
from monitor_module import get_current_client_roles, get_current_policies, get_current_realm_roles

@pytest.mark.skip(reason="This test is skipped because existing realm roles are changing during testing so assert fails.. (TO BE FIXED)")
def test_get_current_realm_roles(keycloak_admin):
    existing_realm_roles_set = get_current_realm_roles(keycloak_admin)
    assert existing_realm_roles_set == {
        "default-roles-master",
        "admin",
        "offline_access",
        "create-realm",
        "uma_authorization",
        "data_engineer",
        "data_curator",
    }

@pytest.mark.skip(reason="This test is skipped because existing client roles and policies are changing during testing so assert fails.. (TO BE FIXED)")
def test_get_client_roles_and_policies(keycloak_admin,minio_admin):
    existing_client_roles_set = get_current_client_roles(keycloak_admin)
    output_lines = minio_admin.policy_list()
    policies = json.loads(output_lines)
    assert existing_client_roles_set == set(policies.keys())-{"writeonly","readonly","readwrite","diagnostics"}
    # assert existing_client_roles_set == output_lines
    # assert output_lines

    
    # assert output_lines