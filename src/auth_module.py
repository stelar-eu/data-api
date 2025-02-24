from typing import Any
from abc import ABC, abstractmethod

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

