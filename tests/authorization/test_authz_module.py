import pytest
import yaml

# Import our module under test.
import authz_module
from authz_module import (
    AuthorizationModule,
    ResourceSpecPermissionsType,
    ResourcePermissionsType,
    AttrSpec,
    GMspec,
    OMSpec,
    UMspec,
    check_access,
    action_permissions,
)

# --- Fake external dependencies ---
def fake_init_admin_client_with_credentials():
    class FakeAdmin:
        def get_client_id(self, client_name):
            return "fake_client_id"
        def get_realm_roles(self, active):
            return []
        def get_client_roles(self, client_id, active):
            # Return list of dicts so that code can access role["name"]
            return [{"name": "fake_client_role_example"}]
        def get_client_role(self, client_id, role_name):
            return f"fake_client_role_{role_name}"
        def add_composite_realm_roles_to_role(self, realm_role, roles):
            pass
        def delete_client_role():
            pass
        def delete_realm_role():
            pass
    return FakeAdmin()

def fake_create_realm_role(admin, role_name):
    return f"realm_{role_name}"

def fake_create_policy(permissions):
    if "action" in permissions:
        return [f"policy_{permissions['action']}"]
    return []

def fake_create_client_role(admin, client, client_id, policy):
    return f"client_role_{policy}"

def fake_get_current_realm_roles(admin):
    return []

def fake_get_current_policies():
    return []

def fake_get_current_client_roles(admin):
    return []

def fake_update_roles_from_yaml(roles_list, existing_roles):
    return []

def fake_update_policies_from_yaml(new_policy_list, existing_policies):
    return ([], set())

def fake_update_client_roles(policy_names_set, existing_client_roles):
    return []

def fake_delete_realm_roles(admin, roles_to_delete):
    pass

def fake_delete_policies(policies_to_delete):
    pass

def fake_delete_client_roles(admin, client_roles_to_delete):
    pass

def fake_ckan_request(method, **kwargs):
    # For testing, return a simple dict.
    if method == "package_show":
        return {
            "id": kwargs.get("id", "unknown"),
            "type": "dataset",
            "groups": [{"name": "group1"}]
        }
    elif method.endswith("_show"):
        return {"id": kwargs.get("resource", "unknown"), "type": method.replace("_show", "")}
    elif method == "member_list":
        # Return a dummy list of members (resource IDs) for group/org membership
        return ["test_resource"]
    return {}

# Replace ckan_request in our module with the fake.
authz_module.ckan_request = fake_ckan_request

# --- Use the central app_context fixture to ensure an application context is active.
# This fixture is defined in your central conftest.py.
@pytest.fixture(autouse=True)
def setup_g(app_context):
    from flask import g
    g.entity = "dataset"
    g.ckan_resources = {}
    g.ckan_group_members = {}
    g.ckan_org_members = {}
    g.current_uid = {"current_uid": "test_uid"}
    yield g

# --- Tests for ResourceSpec classes ---

def test_attr_spec(monkeypatch, app_context,setup_g):
    # Set up the global "context" variable expected by AttrSpec.
    g = setup_g
    authz_module.context = g.current_uid
    # For testing, have fetch_resource return the resource as-is.
    monkeypatch.setattr(AttrSpec, "fetch_resource", lambda self, resource: resource)
    
    spec = AttrSpec(attr="id", operation="equals", value="$current_uid")
    resource = {"id": "test_uid"}
    assert spec(resource) is True

    resource_wrong = {"id": "wrong"}
    assert spec(resource_wrong) is False

    with pytest.raises(ValueError):
        AttrSpec(attr="id", operation="nonexistent", value="value")

def test_gmspec(monkeypatch, app_context):
    # Monkeypatch fetch_resource to return resource unchanged.
    monkeypatch.setattr(GMspec, "fetch_resource", lambda self, resource: resource)
    spec = GMspec(type="server", group="group1", capacity="test_id")
    # Override check_type, check_capacity, and check_group for controlled testing.
    monkeypatch.setattr(spec, "check_type", lambda r: True)
    monkeypatch.setattr(spec, "check_capacity", lambda r: True)
    monkeypatch.setattr(spec, "check_group", lambda r: True)
    
    resource = {"type": "server", "groups": [{"name": "group1"}], "capacity": "test_id"}
    assert spec(resource) is True

    # Simulate group check failure.
    monkeypatch.setattr(spec, "check_group", lambda r: False)
    assert spec(resource) is False

def test_omspec(monkeypatch, app_context):
    monkeypatch.setattr(OMSpec, "fetch_resource", lambda self, resource: resource)
    spec = OMSpec(type="storage", org="org1", capacity="test_id")
    monkeypatch.setattr(spec, "check_org", lambda r: True)
    monkeypatch.setattr(spec, "check_type", lambda r: True)
    monkeypatch.setattr(spec, "check_capacity", lambda r: True)
    
    resource = {"type": "storage", "organization": {"name": "org1"}, "capacity": "test_id"}
    assert spec(resource) is True

    monkeypatch.setattr(spec, "check_org", lambda r: False)
    assert spec(resource) is False

def test_umspec():
    # UMspec checks attributes on the resource object.
    class DummyResource:
        def __init__(self, group, capacity):
            self.group = group
            self.capacity = capacity

    spec = UMspec(group="user", capacity="100")
    resource = DummyResource(group="user", capacity="100")
    assert spec(resource) is True

    resource_bad = DummyResource(group="admin", capacity="100")
    assert spec(resource_bad) is False

# --- Test for global check_access function ---
def test_check_access():
    action_permissions.clear()
    # Create a dummy spec that always returns True.
    class AlwaysTrueSpec:
        def __call__(self, resource):
            return True
    action_permissions["read"] = {"admin": [[AlwaysTrueSpec()]]}
    
    dummy_resource = {}
    assert check_access(["admin"], "read", dummy_resource) is True
    assert check_access(["user"], "read", dummy_resource) is False

    # Test with a failing spec.
    class AlwaysFalseSpec:
        def __call__(self, resource):
            return False
    action_permissions["read"] = {"admin": [[AlwaysTrueSpec(), AlwaysFalseSpec()]]}
    assert check_access(["admin"], "read", dummy_resource) is False

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

# --- Test for ResourcePermissionsType ---
def test_resource_permissions_type_create_permissions(monkeypatch):
    monkeypatch.setattr(authz_module.ku, "init_admin_client_with_credentials", fake_init_admin_client_with_credentials)
    monkeypatch.setattr(authz_module.ku, "create_realm_role", fake_create_realm_role)
    monkeypatch.setattr(authz_module.mu, "create_policy", fake_create_policy)
    monkeypatch.setattr(authz_module.ku, "create_client_role", fake_create_client_role)
    
    fake_admin = fake_init_admin_client_with_credentials()
    fake_admin.get_client_role = lambda client_id, role_name: f"fake_client_role_{role_name}"
    fake_admin.add_composite_realm_roles_to_role = lambda realm_role, roles: None
    monkeypatch.setattr(authz_module.ku, "init_admin_client_with_credentials", lambda: fake_admin)
    
    rpt = ResourcePermissionsType()
    permission = {"action": "read", "resource": "some_resource"}
    rpt.create_permissions("admin", permission)
    assert len(rpt.roles_list) == 1
    assert "policy_read" in rpt.new_policy_list

# --- Test for AuthorizationModule.parse_authz_config ---
def test_parse_authz_config(monkeypatch, app_context):
    action_permissions.clear()
    monkeypatch.setattr(authz_module.ku, "init_admin_client_with_credentials", fake_init_admin_client_with_credentials)
    monkeypatch.setattr(authz_module.ku, "create_realm_role", fake_create_realm_role)
    monkeypatch.setattr(authz_module.mu, "create_policy", fake_create_policy)
    monkeypatch.setattr(authz_module.ku, "create_client_role", fake_create_client_role)
    
    fake_admin = fake_init_admin_client_with_credentials()
    fake_admin.get_client_role = lambda client_id, role_name: f"fake_client_role_{role_name}"
    fake_admin.add_composite_realm_roles_to_role = lambda realm_role, roles: None
    monkeypatch.setattr(authz_module.ku, "init_admin_client_with_credentials", lambda: fake_admin)
    
    monkeypatch.setattr(authz_module.mon, "get_current_realm_roles", fake_get_current_realm_roles)
    monkeypatch.setattr(authz_module.mon, "get_current_policies", fake_get_current_policies)
    monkeypatch.setattr(authz_module.mon, "get_current_client_roles", fake_get_current_client_roles)
    monkeypatch.setattr(authz_module.rec, "update_roles_from_yaml", fake_update_roles_from_yaml)
    monkeypatch.setattr(authz_module.rec, "update_policies_from_yaml", fake_update_policies_from_yaml)
    monkeypatch.setattr(authz_module.rec, "update_client_roles", fake_update_client_roles)
    monkeypatch.setattr(authz_module.ku, "delete_realm_roles", fake_delete_realm_roles)
    monkeypatch.setattr(authz_module.mu, "delete_policies", fake_delete_policies)
    monkeypatch.setattr(authz_module.ku, "delete_client_roles", fake_delete_client_roles)
    
    yaml_config = """
roles:
  - name: "admin"
    permissions:
      - action: "read"
        resource: "some_resource"
  - name: "tester"
    permissions:
      - action: "update"
        resource_spec:
          - attr: "id"
            operation: "equals"
            value: "test_id"
"""
    authz = AuthorizationModule(yaml_config)
    parsed_yaml = yaml.safe_load(yaml_config)
    assert authz.config == parsed_yaml
    # Global action_permissions should contain the tester update permission.
    assert "update" in action_permissions
    assert "tester" in action_permissions["update"]

# --- Test for AuthorizationModule __call__ ---
def test_authorization_module_call(monkeypatch, app_context):
    yaml_config = """
roles:
  - name: "admin"
    permissions:
      - action: "read"
        resource: "some_resource"
"""
    monkeypatch.setattr(authz_module.ku, "init_admin_client_with_credentials", fake_init_admin_client_with_credentials)
    monkeypatch.setattr(authz_module.ku, "create_realm_role", fake_create_realm_role)
    monkeypatch.setattr(authz_module.mu, "create_policy", fake_create_policy)
    monkeypatch.setattr(authz_module.ku, "create_client_role", fake_create_client_role)
    
    fake_admin = fake_init_admin_client_with_credentials()
    fake_admin.get_client_role = lambda client_id, role_name: f"fake_client_role_{role_name}"
    fake_admin.add_composite_realm_roles_to_role = lambda realm_role, roles: None
    monkeypatch.setattr(authz_module.ku, "init_admin_client_with_credentials", lambda: fake_admin)
    
    authz = AuthorizationModule(yaml_config)
    assert authz() == yaml.safe_load(yaml_config)
