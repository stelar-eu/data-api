from typing import Any
from abc import ABC, abstractmethod
import monitor_module as mon
import reconciliation_module as rec
import kutils as ku
import mutils as mu
import yaml

action_permissions = {}

class ResourceSpec(ABC):
    """
    Abstract base class for resource specifications.
    """
    @abstractmethod
    def auth(self,resource) -> bool:
        """
        Determines if a given resource matches this specification.
        """
        pass


class AttrSpec(ResourceSpec):
    def __init__(self, *, attr, operation, value):
        self.attr = attr
        self.operation = operation
        self.value = value
        self.op = getattr(self, self.operation, None)
        if self.op is None:
            raise ValueError("Invalid operation")

    def from_value(self) -> Any:
        "Return the actual value from the value spec"
        if self.value.startswith("$"):
            return self.value_from_context(self.value[1:])
        else:
            return self.value
        
    def value_from_context(self, key) -> Any:
        "Return the value from the context"
        if key not in context:
            match key:
                case "current_uid":
                    return context["current_uid"] 
                case _:
                    raise ValueError("Invalid key")

        return context[key]

    def equals(self, lhs, rhs) -> bool:
        return lhs == rhs
    
    def auth(self, resource):
        lhs = resource.get(self.attr, ...)
        if lhs is ...:
            return False
        rhs = self.from_value()
        return self.op(lhs, rhs)
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)


class GMspec(ResourceSpec):
    def __init__(self, *, type, group, capacity):
        self.type = type
        self.group = group
        self.capacity = capacity

    def auth(self, resource) -> bool:
        if resource.get("type",None) != self.type:
            return False

        if resource.get("group",None) != self.group:
            # self.check_group(resource)
            return False

        if resource.get("capacity",None) != self.capacity:
            return False

        return True
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)
    

class OMSpec(ResourceSpec):
    def __init__(self, *, type, org, capacity):
        self.type = type
        self.org = org
        self.capacity = capacity

    def auth(self, resource, action, context) -> bool:
        if resource.get("type",None) != self.type:
            return False

        if resource.get("owner_org",None) != self.org:
            # self.check_org(resource)
            return False

        if resource.get("capacity",None) != self.capacity:
            return False

        return True
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)
    

class UMspec(ResourceSpec):
    def __init__(self, *, group, capacity):
        self.group = group
        self.capacity = capacity

    def auth(self, resource) -> bool:
        if resource.group != self.group:
            # self.check_group(resource)
            return False

        if resource.capacity != self.capacity:
            return False

        return True
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)



def parse_resource_spec(spec):
    match spec:
        case {"type": t, "group": g, "capacity": c}:
            return GMspec(type=t, group=g, capacity=c)
        case {"type": t, "org": o, "capacity": c}:
            return OMSpec(type=t, org=o, capacity=c)
        case {"group": g, "capacity": c}:
            return UMspec(group=g, capacity=c)
        case {"attr": a, "operation": o, "value": v}:
            return AttrSpec(attr=a, operation=o, value=v)
        case _:
            raise ValueError("Invalid resource specification")


def parse_permissions(role_name,perm):
    global action_permissions

    actions = perm["action"]
    if isinstance(actions, str):
        actions = [actions]  # Normalize to list if a single action is provided

    # Parse resource specs
    resource_specs = [parse_resource_spec(r) for r in perm["resource_spec"]]

    # Build the action-first structure directly
    for action in actions:
        if action not in action_permissions:
            action_permissions[action] = {}

        if role_name not in action_permissions[action]:
            action_permissions[action][role_name] = []

        action_permissions[action][role_name].append(resource_specs)

    # return action_permissions

    
def check_access(user_roles, action, resource):
    global action_permissions
    action_perms = action_permissions.get(action, {})

    # Check across all user roles for that specific action
    for role_name in user_roles:
        role_perms = action_perms.get(role_name, [])

        for resource_specs in role_perms:
            if all(spec(resource) for spec in resource_specs):
                return True  # Early exit on valid permission

    return False  # Denied if no role grants permission



def parse_authz_config(config):
    # initialize keycloak admin through service accounts
        keycloak_admin = ku.init_admin_client_with_credentials()

        # #get minio client id
        client_id = keycloak_admin.get_client_id("minio")

        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(config)
        # yaml_str = request.data

        roles_list = []
        new_policy_list = []

        # Process roles
        for role in yaml_content["roles"]:
            for perm in role["permissions"]:

                match perm:
                    case {"action": a, "resource": p}:
                        
                        role_dict = {
                            "name": role["name"],
                            "permissions": perm,
                            # "resource": perm['resource']
                        }
                        
                        roles_list.append(role_dict)

                        for item in roles_list:
                            role_name = item.get("name")
                            realm_role_name = ku.create_realm_role(keycloak_admin, role_name)
                            policy_name_list = mu.create_policy(item["permissions"])
                            new_policy_list.extend(policy_name_list)
                            for policy in policy_name_list:
                                client_role_name = ku.create_client_role(
                                    keycloak_admin, "minio", client_id, policy
                                )  ##check on that
                                keycloak_admin.add_composite_realm_roles_to_role(
                                    realm_role_name,
                                    [keycloak_admin.get_client_role(client_id, client_role_name)],
                                )

                       
                    case {"action": a, "resource_spec": spec}:
                        
                        parse_permissions(role["name"], perm)

        ########################## reconsile roles and policies ############################
                
        existing_realm_roles = mon.get_current_realm_roles(keycloak_admin)
        existing_policies = mon.get_current_policies()
        existing_client_roles = mon.get_current_client_roles(keycloak_admin)

        roles_to_delete = rec.update_roles_from_yaml(roles_list, existing_realm_roles)
        ku.delete_realm_roles(keycloak_admin, roles_to_delete)

        policies_to_delete, policy_names_set = rec.update_policies_from_yaml(
            new_policy_list, existing_policies
        )
        mu.delete_policies(policies_to_delete)

        client_roles_to_delete = rec.update_client_roles(
            policy_names_set, existing_client_roles
        )
        ku.delete_client_roles(keycloak_admin, client_roles_to_delete)

        return yaml_content
