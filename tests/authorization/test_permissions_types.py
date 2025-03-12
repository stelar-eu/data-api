import pytest
import authz_module
from authz_module import (
    ResourceSpecPermissionsType,
    ResourcePermissionsType,
)
from mutils import generate_random_hash
import json
from conftest import fake_minio_create_policy


# --- Test for ResourceSpecPermissionsType ---
def test_resource_spec_permissions_type_create_permissions():
    rsp = ResourceSpecPermissionsType()
    permission = {
        "action": "update",
        "resource_spec": [
            {"attr": "id", "operation": "equals", "value": "test_value"}
        ]
    }
    result = rsp.create_permissions("tester", permission)
    assert "update" in result
    assert "tester" in result["update"]
    spec_instance = result["update"]["tester"][0][0]
    from authz_module import AttrSpec
    assert isinstance(spec_instance, AttrSpec)

    ####################################################################################################

    permission = {
        "action": "update",
        "resource_spec": [
            {"type": "dataset", "group": "group1", "capacity": "test_value"}
        ]
    }
    result = rsp.create_permissions("tester", permission)
    assert "update" in result
    assert "tester" in result["update"]
    spec_instance = result["update"]["tester"][0][0]
    from authz_module import GMspec
    assert isinstance(spec_instance, GMspec)

    ####################################################################################################

    permission = {
        "action": "update",
        "resource_spec": [
            {"type": "dataset", "org": "org1", "capacity": "test_value"}
        ]
    }
    result = rsp.create_permissions("tester", permission)
    assert "update" in result
    assert "tester" in result["update"]
    spec_instance = result["update"]["tester"][0][0]
    from authz_module import OMSpec
    assert isinstance(spec_instance, OMSpec)

    ####################################################################################################

    permission = {
        "action": "update",
        "resource_spec": [
            {"group": "group1", "capacity": "test_value"}
        ]
    }
    result = rsp.create_permissions("tester", permission)
    assert "update" in result
    assert "tester" in result["update"]
    spec_instance = result["update"]["tester"][0][0]
    from authz_module import UMspec
    assert isinstance(spec_instance, UMspec)

# --- Test for ResourcePermissionsType ---
def test_resource_permissions_type_create_permissions(app, monkeysession,minio_admin,keycloak_admin):
    with app.app_context():
        # Bind the fixture to the fake function via a lambda
        monkeysession.setattr(
            authz_module.mu, 
            "create_policy", 
            lambda perm: fake_minio_create_policy(minio_admin,perm)
        )
    
        rpt = ResourcePermissionsType()
        permission = {"action": "read", "resource": "bucket/foo/bar"}
        rpt.create_permissions("tester", permission)

        assert len(rpt.roles_list) == 1
        assert rpt.new_policy_list

        keycloak_admin.delete_client_role(rpt.client_id,rpt.new_policy_list[0])
        keycloak_admin.delete_realm_role("tester")
        minio_admin.policy_remove(rpt.new_policy_list[0])

        