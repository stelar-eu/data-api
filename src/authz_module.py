from typing import Any
from abc import ABC, abstractmethod
import monitor_module as mon
import reconciliation_module as rec
import kutils as ku
import mutils as mu
import yaml
import logging
from flask import g,jsonify
from backend.ckan import ckan_request
import fnmatch

logger = logging.getLogger(__name__)

action_permissions = {}

class AuthorizationModule:

    def __init__(self, config):
        logger.info("Initializing the Authorization Module")
        self.config = self.parse_authz_config(config)

    def create_permissions(self, role_name, perm):
        raise NotImplementedError

    def reconcile(self):
        raise NotImplementedError
    
    def parse_authz_config(self,config):
        new_permissions = {}
        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(config)
        
        logging.info("Parsing the yaml file")
        resource_obj = ResourcePermissionsType()
        resource_spec_obj = ResourceSpecPermissionsType()
        # Process roles
        for role in yaml_content["roles"]:
            for perm in role["permissions"]:
                match perm:
                    case {"action": a, "resource": p}:
                        logger.info("Processing resourceType permissions")
                        resource_obj.create_permissions(role["name"],perm)   
                    case {"action": a, "resource_spec": spec}:
                        logger.info("Processing resourceSpecType permissions")
                        new_perms = resource_spec_obj.create_permissions(role["name"], perm)
                        for key, value in new_perms.items():
                            if key in new_permissions:
                                # Merge nested dict: key -> role_name -> list of specs.
                                for role_name, specs in value.items():
                                    if role_name in new_permissions[key]:
                                        new_permissions[key][role_name].extend(specs)
                                    else:
                                        new_permissions[key][role_name] = specs
                            else:
                                new_permissions[key] = value

        ########################## reconsile roles and policies ############################
        resource_obj.reconcile()
        resource_spec_obj.reconcile(new_permissions)    
        
        return yaml_content

    def __call__(self):
        return self.config
    
class ResourceSpecPermissionsType(AuthorizationModule):

    def __init__(self):
        pass
    
    def parse_resource_spec(self,spec):
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
                  
    def create_permissions(self,role_name, perm):
    
        permissions = {}
        
        logger.info("Creating resource_spec permissions")
        actions = perm["action"]
        if isinstance(actions, str):
            actions = [actions]  # Normalize to list if a single action is provided
        logger.info("Parsing resource specs")
        # Parse resource specs
        resource_specs = [self.parse_resource_spec(r) for r in perm["resource_spec"]]

        # Build the action-first structure directly
        for action in actions:
            if action not in permissions:
                permissions[action] = {}

            if role_name not in permissions[action]:
                permissions[action][role_name] = []

            permissions[action][role_name].append(resource_specs)
        
        return permissions
       
    def reconcile(self,new_permissions):
        global action_permissions
        action_permissions = new_permissions

        
    
class ResourcePermissionsType(AuthorizationModule):

    def __init__(self):
        logger.info("Initializing ResourcePermissionsType")
        self.roles_list = []
        self.new_policy_list = []
        self.keycloak_admin = ku.init_admin_client_with_credentials()
        self.client_id = self.keycloak_admin.get_client_id("minio")

    
    def create_permissions(self, role, perm):
        logger.info("Creating role dict")
        role_dict = {
            "name": role,
            "permissions": perm,
            # "resource": perm['resource']
        }
        logger.info("Appending role dict to roles_list")
        self.roles_list.append(role_dict)

        logger.info("Creating roles and policies")
        for item in self.roles_list:
            role_name = item.get("name")
            realm_role_name = ku.create_realm_role(self.keycloak_admin, role_name)
            policy_name_list = mu.create_policy(item["permissions"])
            self.new_policy_list.extend(policy_name_list)
            for policy in policy_name_list:
                client_role_name = ku.create_client_role(
                    self.keycloak_admin, "minio", self.client_id, policy
                )  ##check on that
                self.keycloak_admin.add_composite_realm_roles_to_role(
                    realm_role_name,
                    [self.keycloak_admin.get_client_role(self.client_id, client_role_name)],
                )
        logger.info("Role and policy creation completed")
            

    def reconcile(self):
        existing_realm_roles = mon.get_current_realm_roles(self.keycloak_admin)
        existing_policies = mon.get_current_policies()
        existing_client_roles = mon.get_current_client_roles(self.keycloak_admin)

        roles_to_delete = rec.update_roles_from_yaml(self.roles_list, existing_realm_roles)
        ku.delete_realm_roles(self.keycloak_admin, roles_to_delete)

        policies_to_delete, policy_names_set = rec.update_policies_from_yaml(
            self.new_policy_list, existing_policies
        )
        mu.delete_policies(policies_to_delete)

        client_roles_to_delete = rec.update_client_roles(
            policy_names_set, existing_client_roles
        )
        ku.delete_client_roles(self.keycloak_admin, client_roles_to_delete)


class ResourceSpec:
    """
    Abstract base class for resource specifications.
    """
    
    def auth(self,resource) -> bool:
        """
        Determines if a given resource matches this specification.
        """
        raise NotImplementedError


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

        user_info = ku.current_user()
        match key:
            case "current_uid":
                return user_info["sub"]
            case _:
                raise ValueError("Invalid key")

    def equals(self, lhs, rhs) -> bool:
        logger.info("Checking equals")
        return lhs == rhs
    
    #TODO Implement the rest of the operations
    def like(self, lhs, rhs) -> bool:
        logger.info("Checking like")
        return fnmatch.fnmatch(lhs, rhs)

    def between(self, lhs, rhs) -> bool:
        pass

    def from_date(self, lhs, rhs) -> bool:
        pass

    
    def auth(self, resource):
        fetched_resource = fetch_resource("fetch_resource", resource)
        lhs = fetched_resource.get(self.attr, ...)
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

    def check_group(self, resource):
        # When resource is provided as an ID (string), check against the cached group members.
        if isinstance(resource, str):
            logger.info("Checking group with resource id")
            group_members = fetch_resource("fetch_group_members", self.group)
            for member in group_members:
                logger.info("Checking member")
                if resource in member:
                    logger.info("Resource found in group")
                    return True
            return False
        else:
            groups = resource.get("groups", None)
            if groups:
                for group in groups:
                    if group.get("name", None) == self.group:
                        return True
            return False

    def check_type(self, resource):
        logger.info("Checking type")
        resource = fetch_resource("fetch_resource", resource)
        if resource.get("type", None) != self.type:
            return False
        return True

    def check_capacity(self, resource):
        logger.info("Checking capacity")
        if isinstance(resource, str):
            logger.info("Checking group for capacity")
            group_members = fetch_resource("fetch_group_members", self.group)
            for member in group_members:
                logger.info("Checking member for capacity")
                if resource in member and self.capacity in member:
                    return True
            return False
        return False


    def auth(self, resource) -> bool:

        if not self.check_group(resource):
            return False
        
        if not self.check_type(resource):
            return False
        
        if not self.check_capacity(resource):
            return False

        return True
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)
    

class OMSpec(ResourceSpec):
    def __init__(self, *, type, org, capacity):
        self.type = type
        self.org = org
        self.capacity = capacity

    def check_org(self, resource):
        # When resource is provided as an ID (string), check against the cached group members.
        if isinstance(resource, str):
            logger.info("Checking org with resource id")
            org_members = fetch_resource("fetch_org_members", self.org)
            for member in org_members:
                logger.info("Checking member")
                if resource in member:
                    logger.info("Resource found in org")
                    return True
            return False
        else:
            org = resource.get("organization", None)
            if org and org.get("name", None) == self.org:
                    return True
            return False

    def check_type(self, resource):
        logger.info("Checking type")
        resource = fetch_resource("fetch_resource", resource)
        if resource.get("type", None) != self.type:
            return False
        return True

    def check_capacity(self, resource):
        logger.info("Checking capacity")
        if isinstance(resource, str):
            logger.info("Checking org for capacity")
            group_members = fetch_resource("fetch_org_members", self.org)
            for member in group_members:
                logger.info("Checking member for capacity")
                if resource in member and self.capacity in member:
                    return True
            return False
        return False


    def auth(self, resource) -> bool:
        if not self.check_org(resource):
            return False
        
        if not self.check_type(resource):
            return False
        
        if not self.check_capacity(resource):
            return False

        return True
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)


class UMspec(ResourceSpec):
    def __init__(self, *, group, capacity):
        self.group = group
        self.capacity = capacity

    def check_group(self, resource):
        members = fetch_resource("fetch_group_members", self.group)
        user_info = ku.current_user()
        for member in members:
            if user_info["sub"] in member:
                return True
        return False
    
    def check_capacity(self, resource):
        members = fetch_resource("fetch_group_members", self.group)
        user_info = ku.current_user()
        for member in members:
            if user_info["sub"] in member and self.capacity in member:
                return True
        return False

    def auth(self, resource) -> bool:
        if not self.check_group(resource):
            # self.check_group(resource)
            return False

        if not self.check_capacity(resource):
            return False

        return True
    
    def __call__(self, resource) -> bool:
        return self.auth(resource)

#TODO: Move this function to backed/ckan.py 
def fetch_resource(purpose,*args):
    # Cache the resource in flask.g.ckan_resources if resource is given as an ID (a string)
    logger.info("Now all calls the general puprose function")
    if purpose == "fetch_resource":
        if isinstance(args[0], str):
            if not hasattr(g, "ckan_resources"):
                g.ckan_resources = {}
            if args[0] in g.ckan_resources:
                logger.info("Resource retrieved from flask.g cache")
                return g.ckan_resources[args[0]]
            if g.entity and g.entity in ["dataset", "workflow", "process", "tool"]:
                logger.info("ckan request for package show")
                fetched = ckan_request("package_show", id=args[0], context={"entity": g.entity})
                logger.info("Resource fetched from CKAN")
            else:
                fetched = ckan_request(f"{g.entity}_show", id=args[0])
            g.ckan_resources[args[0]] = fetched
            return fetched
        else:
            return args[0]
    elif purpose == "fetch_group_members":
        if not hasattr(g, "ckan_group_members"):
            g.ckan_group_members = {}
        if args[0] in g.ckan_group_members:
            logger.info("Group members retrieved from flask.g cache")
            return g.ckan_group_members[args[0]]
        try:
            members = ckan_request("member_list", id=args[0])
        except Exception:
            raise ValueError("Group does not exist")
        g.ckan_group_members[args[0]] = members
        return members
    elif purpose == "fetch_org_members":
        if not hasattr(g, "ckan_org_members"):
            g.ckan_org_members = {}
        if args[0] in g.ckan_org_members:
            logger.info("Org members retrieved from flask.g cache")
            return g.ckan_org_members[args[0]]
        try:
            members = ckan_request("member_list", id=args[0])
        except Exception:
            raise ValueError("Group does not exist")
        g.ckan_org_members[args[0]] = members
        return members
    else:
        return None



def check_access(user_roles, action, resource):
    global action_permissions
    action_perms = action_permissions.get(action, {})

    #Fetch the actual resource else take the input data
    # if isinstance(resource, dict):
    #     resource = resource
    # else:
    #     resource = ckan_request("package_show", resource)

    # Check across all user roles for that specific action
    for role_name in user_roles:
        role_perms = action_perms.get(role_name, [])

        for resource_specs in role_perms:
            if all(spec(resource) for spec in resource_specs):
                return True  # Early exit on valid permission

    return False  # Denied if no role grants permission