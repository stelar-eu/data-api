import pytest
import yaml

# --- Fake implementations for external dependencies ---

def fake_init_admin_client_with_credentials():
    class FakeAdmin:
        def get_client_id(self, client_name):
            return "fake_client_id"

        def get_realm_roles(self, active):
            return []  # or a fake list of roles as needed

        def get_client_roles(self, client_id, active):
            # Return a list of dicts so that code can iterate and access the "name" key.
            return [{"name": "fake_client_role_example"}]

        def get_client_role(self, client_id, role_name):
            return f"fake_client_role_{role_name}"

        def add_composite_realm_roles_to_role(self, realm_role_name, roles):
            pass
        
        def delete_realm_role(self, role_name):
            pass

        def delete_client_role(self, client_id, role_name):
            pass

    return FakeAdmin()



def fake_create_realm_role(admin, role_name):
    return f"realm_{role_name}"

def fake_create_policy(permissions):
    # For testing, return a list with one policy string based on the action.
    if "action" in permissions:
        return [f"policy_{permissions['action']}"]
    return []

def fake_create_client_role(admin, client, client_id, policy):
    return f"client_role_{policy}"

# --- Tests for Resource Specification classes ---

def test_attr_spec(monkeypatch):
    # Ensure that the AttrSpec correctly uses context for "$" values.
    # Set a global context in the module under test.
    import authz_module
    authz_module.context = {"current_uid": "user1"}
    
    spec = authz_module.AttrSpec(attr="id", operation="equals", value="$current_uid")
    resource = {"id": "user1"}
    assert spec(resource) is True

    spec2 = authz_module.AttrSpec(attr="id", operation="equals", value="user2")
    resource2 = {"id": "user2"}
    assert spec2(resource2) is True
    resource3 = {"id": "user3"}
    assert spec2(resource3) is False

    with pytest.raises(ValueError):
        authz_module.AttrSpec(attr="id", operation="nonexistent", value="user")

def test_gmspec():
    from authz_module import GMspec
    spec = GMspec(type="server", group="admin", capacity=10)
    resource = {"type": "server", "group": "admin", "capacity": 10}
    assert spec(resource) is True

    resource2 = {"type": "server", "group": "user", "capacity": 10}
    assert spec(resource2) is False

def test_omspec():
    from authz_module import OMSpec
    spec = OMSpec(type="storage", org="org1", capacity=50)
    resource = {"type": "storage", "owner_org": "org1", "capacity": 50}
    assert spec(resource) is True

    resource2 = {"type": "storage", "owner_org": "org2", "capacity": 50}
    assert spec(resource2) is False

class DummyResource:
    def __init__(self, group, capacity):
        self.group = group
        self.capacity = capacity

def test_umspec():
    from authz_module import UMspec
    spec = UMspec(group="user", capacity=100)
    resource = DummyResource(group="user", capacity=100)
    assert spec(resource) is True

    resource2 = DummyResource(group="admin", capacity=100)
    assert spec(resource2) is False

# --- Test for check_access ---
def test_check_access():
    from authz_module import check_access, action_permissions, AttrSpec
    # Clear any existing permissions.
    action_permissions.clear()
    
    # Dummy spec that always returns True.
    class AlwaysTrueSpec:
        def __call__(self, resource):
            return True

    action_permissions["read"] = {"admin": [[AlwaysTrueSpec()]]}
    resource = {}
    assert check_access(["admin"], "read", resource) is True
    assert check_access(["user"], "read", resource) is False

    # Test with one spec failing.
    class AlwaysFalseSpec:
        def __call__(self, resource):
            return False

    action_permissions["read"] = {"admin": [[AlwaysTrueSpec(), AlwaysFalseSpec()]]}
    assert check_access(["admin"], "read", resource) is False

# --- Tests for ResourceSpecPermissionsType ---
def test_resource_spec_permissions_type_create_permissions():
    from authz_module import ResourceSpecPermissionsType, AttrSpec
    permission = {
        "action": "update",
        "resource_spec": [
            {"attr": "id", "operation": "equals", "value": "test_id"}
        ]
    }
    rsp = ResourceSpecPermissionsType()
    result = rsp.create_permissions("tester", permission)
    # The structure should be: { "update": { "tester": [ [<AttrSpec instance>] ] } }
    assert "update" in result
    assert "tester" in result["update"]
    assert isinstance(result["update"]["tester"][0][0], AttrSpec)

# --- Tests for ResourcePermissionsType ---
def test_resource_permissions_type_create_permissions(monkeypatch):
    from authz_module import ResourcePermissionsType
    import authz_module as am
    # Override external dependency functions.
    monkeypatch.setattr(am.ku, "init_admin_client_with_credentials", fake_init_admin_client_with_credentials)
    monkeypatch.setattr(am.ku, "create_realm_role", fake_create_realm_role)
    monkeypatch.setattr(am.mu, "create_policy", fake_create_policy)
    monkeypatch.setattr(am.ku, "create_client_role", fake_create_client_role)
    
    # Prepare a fake admin object with additional methods.
    fake_admin = fake_init_admin_client_with_credentials()
    fake_admin.get_client_role = lambda client_id, role_name: f"fake_client_role_{role_name}"
    fake_admin.add_composite_realm_roles_to_role = lambda realm_role, roles: None
    monkeypatch.setattr(am.ku, "init_admin_client_with_credentials", lambda: fake_admin)

    rperm = ResourcePermissionsType()
    permission = {"action": "read", "resource": "some_resource"}
    rperm.create_permissions("admin", permission)
    # After creation, roles_list should have one role dict and new_policy_list should contain a policy.
    assert len(rperm.roles_list) == 1
    assert "policy_read" in rperm.new_policy_list

#  Tests for AuthorizationModule.parse_authz_config and __call__ ---
def test_parse_authz_config(monkeypatch):
    from authz_module import AuthorizationModule, action_permissions
    import authz_module as am
    
    # YAML config with one resource permission and one resource_spec permission.
    yaml_config = """
roles:
  - name: admin
    permissions:
      - action: read
        resource: some_resource
  - name: tester
    permissions:
      - action: update
        resource_spec:
          - attr: id
            operation: equals
            value: "test_id"
"""
    # Monkeypatch external dependencies used in ResourcePermissionsType.
    monkeypatch.setattr(am.ku, "init_admin_client_with_credentials", fake_init_admin_client_with_credentials)
    monkeypatch.setattr(am.ku, "create_realm_role", fake_create_realm_role)
    monkeypatch.setattr(am.mu, "create_policy", fake_create_policy)
    monkeypatch.setattr(am.ku, "create_client_role", fake_create_client_role)
    fake_admin = fake_init_admin_client_with_credentials()
    fake_admin.get_client_role = lambda client_id, role_name: f"fake_client_role_{role_name}"
    fake_admin.add_composite_realm_roles_to_role = lambda realm_role, roles: None
    monkeypatch.setattr(am.ku, "init_admin_client_with_credentials", lambda: fake_admin)

    authz = AuthorizationModule(yaml_config)
    # The returned config should match the parsed YAML.
    assert authz() == yaml.safe_load(yaml_config)
    # Global action_permissions should now contain the tester update permission.
    assert "update" in action_permissions
    assert "tester" in action_permissions["update"]

def test_authorization_module_call(monkeypatch):
    from authz_module import AuthorizationModule
    import authz_module as am
    yaml_config = """
roles:
  - name: admin
    permissions:
      - action: read
        resource: some_resource
"""
    # Monkeypatch external functions for ResourcePermissionsType.
    monkeypatch.setattr(am.ku, "init_admin_client_with_credentials", fake_init_admin_client_with_credentials)
    monkeypatch.setattr(am.ku, "create_realm_role", fake_create_realm_role)
    monkeypatch.setattr(am.mu, "create_policy", fake_create_policy)
    monkeypatch.setattr(am.ku, "create_client_role", fake_create_client_role)
    fake_admin = fake_init_admin_client_with_credentials()
    fake_admin.get_client_role = lambda client_id, role_name: f"fake_client_role_{role_name}"
    fake_admin.add_composite_realm_roles_to_role = lambda realm_role, roles: None
    monkeypatch.setattr(am.ku, "init_admin_client_with_credentials", lambda: fake_admin)
    
    authz = AuthorizationModule(yaml_config)
    # Calling the instance should return the parsed configuration.
    assert authz() == yaml.safe_load(yaml_config)
