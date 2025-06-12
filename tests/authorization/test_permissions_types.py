import json

import pytest
from conftest import fake_minio_create_policy

import authz_module
from authz_module import ResourcePermissionsType, ResourceSpecPermissionsType
from mutils import generate_random_hash


# --- Test for ResourceSpecPermissionsType ---
@pytest.mark.skip()
def test_resource_spec_permissions_type_create_permissions():
    authz_module.new_permissions.clear()
    rsp = ResourceSpecPermissionsType()
    permission = {
        "action": "update",
        "resource_spec": [{"attr": "id", "operation": "equals", "value": "test_value"}],
    }
    rsp.create_permissions("tester", permission)
    assert "update" in authz_module.new_permissions
    assert "tester" in authz_module.new_permissions["update"]
    spec_instance = authz_module.new_permissions["update"]["tester"][0]
    from authz_module import AttrSpec

    assert isinstance(spec_instance, AttrSpec)

    ####################################################################################################

    permission = {
        "action": "update",
        "resource_spec": [
            {"type": "dataset", "group": "group1", "capacity": "test_value"}
        ],
    }
    rsp.create_permissions("tester", permission)
    assert "update" in authz_module.new_permissions
    assert "tester" in authz_module.new_permissions["update"]
    spec_instance = authz_module.new_permissions["update"]["tester"][1]
    from authz_module import GMspec

    assert isinstance(spec_instance, GMspec)

    ####################################################################################################

    permission = {
        "action": "update",
        "resource_spec": [{"type": "dataset", "org": "org1", "capacity": "test_value"}],
    }
    rsp.create_permissions("tester", permission)
    assert "update" in authz_module.new_permissions
    assert "tester" in authz_module.new_permissions["update"]
    spec_instance = authz_module.new_permissions["update"]["tester"][2]
    from authz_module import GMspec

    assert isinstance(spec_instance, GMspec)

    ####################################################################################################

    permission = {
        "action": "update",
        "resource_spec": [{"group": "group1", "capacity": "test_value"}],
    }
    rsp.create_permissions("tester", permission)
    assert "update" in authz_module.new_permissions
    assert "tester" in authz_module.new_permissions["update"]
    spec_instance = authz_module.new_permissions["update"]["tester"][3]
    from authz_module import UMspec

    assert isinstance(spec_instance, UMspec)

    ####################################################################################################

    permission = {
        "action": "read",
        "resource_spec": [
            {"group": "group1", "capacity": "test_value"},
            {"type": "dataset", "org": "org1", "capacity": "test_value"},
        ],
    }
    rsp.create_permissions("tester", permission)
    assert "update" in authz_module.new_permissions
    assert "read" in authz_module.new_permissions
    assert "tester" in authz_module.new_permissions["update"]
    assert "tester" in authz_module.new_permissions["read"]
    um_spec_instance = authz_module.new_permissions["read"]["tester"][0]
    attr_spec_instance = authz_module.new_permissions["read"]["tester"][1]
    spec_instance = authz_module.new_permissions["update"]["tester"][3]
    from authz_module import UMspec

    assert isinstance(spec_instance, UMspec)
    assert isinstance(um_spec_instance, UMspec)
    assert isinstance(attr_spec_instance, GMspec)

    ####################################################################################################

    authz_module.new_permissions.clear()


# --- Test for ResourcePermissionsType ---
@pytest.mark.skip()
def test_resource_permissions_type_create_permissions(
    app, monkeysession, minio_admin, keycloak_admin
):
    with app.app_context():
        # Bind the fixture to the fake function via a lambda
        monkeysession.setattr(
            authz_module.mu,
            "create_policy",
            lambda perm: fake_minio_create_policy(minio_admin, perm),
        )

        rpt = ResourcePermissionsType()
        permission = {"action": "read", "resource": "bucket/foo/bar"}
        rpt.create_permissions("tester", permission)

        assert len(rpt.roles_list) == 1
        assert rpt.new_policy_list

        keycloak_admin.delete_client_role(rpt.client_id, rpt.new_policy_list[0])
        keycloak_admin.delete_realm_role("tester")
        minio_admin.policy_remove(rpt.new_policy_list[0])
