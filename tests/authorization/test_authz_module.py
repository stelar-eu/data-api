import pytest
import yaml

# Import our module under test.
import authz_module
from authz_module import (
    AuthorizationModule,
    check_access,
)

from conftest import fake_minio_create_policy


# --- Test for global check_access function ---
def test_check_access():
    authz_module.action_permissions.clear()
    # Create a dummy spec that always returns True.
    class AlwaysTrueSpec:
        def __call__(self, resource):
            return True
    authz_module.action_permissions["read"] = {"admin": [[AlwaysTrueSpec()]]}
    
    dummy_resource = {}
    assert check_access(["admin"], "read", dummy_resource) is True
    assert check_access(["user"], "read", dummy_resource) is False

    # Test with a failing spec.
    class AlwaysFalseSpec:
        def __call__(self, resource):
            return False
    authz_module.action_permissions["read"] = {"admin": [[AlwaysTrueSpec(), AlwaysFalseSpec()]]}
    assert check_access(["admin"], "read", dummy_resource) is False



# --- Test for AuthorizationModule.parse_authz_config ---
def test_parse_authz_config(monkeysession,app,minio_admin):
    with app.app_context():
      authz_module.action_permissions.clear()
      
      yaml_config = """
  roles:
    - name: "tester_1"
      permissions:
        - action: "read"
          resource: "bucket2/bar/foo"
    - name: "tester"
      permissions:
        - action: "update"
          resource_spec:
            - attr: "id"
              operation: "equals"
              value: "test_id"
  """
      monkeysession.setattr(
            authz_module.mu, 
            "create_policy", 
            lambda perm: fake_minio_create_policy(minio_admin,perm)
      )
      authz = AuthorizationModule(yaml_config)
      parsed_yaml = yaml.safe_load(yaml_config)
      assert authz.config == parsed_yaml
      # Global authz_module.action_permissions should contain the tester update permission.
      assert "update" in authz_module.action_permissions
      assert "tester" in authz_module.action_permissions["update"]