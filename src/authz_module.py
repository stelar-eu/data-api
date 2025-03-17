"""
Authorization Module
--------------------
This module implements an authorization system that verifies user access
to resources based on roles and resource specifications. It integrates with
external systems such as CKAN for resource retrieval and Keycloak for role
and policy management.

Modules included:
    - AuthorizationModule: Abstract base class for authorization.
    - ResourceSpecPermissionsType: Handles resource specification based permissions.
    - ResourcePermissionsType: Handles direct resource type based permissions.
    - ResourceSpec and its subclasses (AttrSpec, GMspec, OMSpec, UMspec): 
      Defines resource specifications and their authorization logic.
    - Utility functions: fetch_resource (for resource caching and retrieval)
      and check_access (for validating user permissions based on roles).

Usage:
    Initialize the AuthorizationModule with a YAML configuration to parse roles
    and permissions. Use check_access to determine if a user with specific roles
    is allowed to perform an action on a resource.
"""

from typing import Any
from abc import ABC, abstractmethod
import monitor_module as mon
import reconciliation_module as rec
import kutils as ku
import mutils as mu
import yaml
import logging
from flask import g, jsonify
from backend.ckan import ckan_request
import fnmatch

logger = logging.getLogger(__name__)

# Global dictionary to store permissions mapped by action.
action_permissions = {}
# Global dictionary to store new permissions during parsing(For reconciliation purposes).
new_permissions = {}


class AuthorizationModule:
    """
    Base class for the authorization framework.
    
    This class is responsible for parsing the YAML configuration,
    creating permissions, and reconciling them with the external systems.
    """

    def __init__(self, config):
        """
        Initialize the Authorization Module with a YAML configuration.
        
        Args:
            config (str): YAML configuration string defining roles and permissions.
        """
        logger.info("Initializing the Authorization Module")
        self.config = self.parse_authz_config(config)

    def create_permissions(self, role_name, perm):
        """
        Abstract method to create permissions for a given role.
        
        Args:
            role_name (str): The name of the role.
            perm (dict): Permission definition.
        
        Raises:
            NotImplementedError: Must be implemented in subclasses.
        """
        raise NotImplementedError

    def reconcile(self):
        """
        Abstract method to reconcile current permissions with the external system.
        
        Raises:
            NotImplementedError: Must be implemented in subclasses.
        """
        raise NotImplementedError

    def parse_authz_config(self, config):
        """
        Parse the YAML configuration and initialize permission structures.
        
        This method processes roles and their associated permissions, 
        delegating to ResourcePermissionsType and ResourceSpecPermissionsType.
        
        Args:
            config (str): YAML configuration string.
        
        Returns:
            dict: The parsed YAML configuration.
        """
        # Read the file content and load it as a dictionary.
        yaml_content = yaml.safe_load(config)
        
        logging.info("Parsing the yaml file")
        resource_obj = ResourcePermissionsType()
        resource_spec_obj = ResourceSpecPermissionsType()
        # Process roles defined in the configuration.
        for role in yaml_content["roles"]:
            for perm in role["permissions"]:
                match perm:
                    case {"action": a, "resource": p}:
                        logger.info("Processing resourceType permissions")
                        resource_obj.create_permissions(role["name"], perm)
                    case {"action": a, "resource_spec": spec}:
                        logger.info("Processing resourceSpecType permissions")
                        resource_spec_obj.create_permissions(role["name"], perm)

        # Reconcile roles and policies.
        resource_obj.reconcile()
        resource_spec_obj.reconcile()

        logger.info("Parsing completed")
        logger.info(f"New permissions: {action_permissions}")
        
        return yaml_content

    def __call__(self):
        """
        Allow the instance to be called to retrieve its configuration.
        
        Returns:
            dict: Parsed configuration.
        """
        return self.config


class ResourceSpecPermissionsType(AuthorizationModule):
    """
    Handles permissions defined with resource specifications ("resource_spec" in YAML).
    This class converts raw specifications into concrete resource specification objects.
    """

    def __init__(self):
        # No initialization parameters required.
        pass
    
    def parse_resource_spec(self, spec):
        """
        Parse a resource specification dictionary into a resource spec object.
        
        The function uses pattern matching to determine the type of resource spec.
        
        Args:
            spec (dict): The resource specification dictionary.
        
        Returns:
            ResourceSpec: An instance of a ResourceSpec subclass.
        
        Raises:
            ValueError: If the specification format is invalid.
        """
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
                  
    
    def create_permissions(self, role_name, perm):
        """
        Create permissions based on resource specifications and update the global new_permissions.
        
        The permissions are stored in a global dictionary with the following structure:
        
        {
            "action": {
                "role_name": [ list of parsed resource spec objects ]
            }
        }
        
        Args:
            role_name (str): The name of the role.
            perm (dict): The permission definition containing action and resource_spec.
        """
        global new_permissions
        logger.info("Creating resource_spec permissions")
        
        # Normalize the action field to a list if it is not already.
        actions = perm["action"]
        if isinstance(actions, str):
            actions = [actions]
        
        logger.info("Parsing resource specs")
        # Parse each resource specification into a resource spec object.
        parsed_specs = [self.parse_resource_spec(r) for r in perm["resource_spec"]]
        
        # Merge the parsed specs into the global dictionary.
        for action in actions:
            if action not in new_permissions:
                new_permissions[action] = {}
            if role_name not in new_permissions[action]:
                new_permissions[action][role_name] = []
            # Instead of appending a list of specs, extend to add each spec individually.
            new_permissions[action][role_name].extend(parsed_specs)


        
    def reconcile(self):
        """
        Reconcile resource specification permissions by updating the global permissions.
        """
        global action_permissions, new_permissions
        action_permissions = new_permissions.copy()

        new_permissions.clear()


class ResourcePermissionsType(AuthorizationModule):
    """
    Handles permissions based on direct resource types ("resource" in YAML).
    
    This class is responsible for creating roles and policies in Keycloak based on
    the YAML configuration, and for reconciling these with existing roles and policies.
    """

    def __init__(self):
        """
        Initialize the ResourcePermissionsType and prepare Keycloak client details.
        """
        logger.info("Initializing ResourcePermissionsType")
        self.roles_list = []
        self.new_policy_list = []
        self.keycloak_admin = ku.init_admin_client_with_credentials()
        self.client_id = self.keycloak_admin.get_client_id("minio")

    def create_permissions(self, role, perm):
        """
        Create permissions for a given role based on resource type.
        
        This method builds a role dictionary, creates realm roles, generates policies,
        and creates client roles in Keycloak.
        
        Args:
            role (str): The role name.
            perm (dict): Permission details.
        """
        logger.info("Creating role dict")
        role_dict = {
            "name": role,
            "permissions": perm,
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
                )  # Create client role for policy.
                self.keycloak_admin.add_composite_realm_roles_to_role(
                    realm_role_name,
                    [self.keycloak_admin.get_client_role(self.client_id, client_role_name)],
                )
        logger.info("Role and policy creation completed")

    def reconcile(self):
        """
        Reconcile the roles and policies from the YAML configuration with existing ones.
        
        This involves:
          - Retrieving current realm roles, policies, and client roles.
          - Determining roles and policies that need to be deleted.
          - Deleting outdated roles, policies, and client roles.
        """
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
    
    Resource specifications define criteria that a resource must meet to be authorized.
    Subclasses must implement the auth() method.
    """
    
    @abstractmethod
    def auth(self, resource) -> bool:
        """
        Determine if a given resource matches this specification.
        
        Args:
            resource (Any): The resource to check against the specification.
        
        Returns:
            bool: True if the resource meets the specification, False otherwise.
        """
        raise NotImplementedError


class AttrSpec(ResourceSpec):
    """
    Implements an attribute-based resource specification.
    
    This class verifies that a resource attribute meets a specified condition.
    """

    def __init__(self, *, attr, operation, value):
        """
        Initialize an attribute specification.
        
        Args:
            attr (str): The attribute name to compare.
            operation (str): The operation to perform (e.g., "equals", "like").
            value (str): The value to compare against. A value starting with '$' indicates
                         that the value should be fetched dynamically from the user context.
        
        Raises:
            ValueError: If the operation is invalid.
        """
        self.attr = attr
        self.operation = operation
        self.value = value
        self.op = getattr(self, self.operation, None)
        if self.op is None:
            raise ValueError("Invalid operation")

    def from_value(self) -> Any:
        """
        Return the actual value to compare against.
        
        If the value starts with '$', it is fetched dynamically from the user context.
        
        Returns:
            Any: The value to use for comparison.
        """
        if self.value.startswith("$"):
            return self.value_from_context(self.value[1:])
        else:
            return self.value
        
    def value_from_context(self, key) -> Any:
        """
        Retrieve dynamic values from the current user context.
        
        Args:
            key (str): The key to lookup in the context.
        
        Returns:
            Any: The value from the current user context.
        
        Raises:
            ValueError: If the key is invalid.
        """
        user_info = ku.current_user()
        match key:
            case "current_uid":
                return user_info["sub"]
            case _:
                raise ValueError("Invalid key")

    def equals(self, lhs, rhs) -> bool:
        """
        Check if two values are equal.
        
        Args:
            lhs (Any): Left-hand side value.
            rhs (Any): Right-hand side value.
        
        Returns:
            bool: True if values are equal, otherwise False.
        """
        logger.info("Checking equals")
        return lhs == rhs
    
    def like(self, lhs, rhs) -> bool:
        """
        Check if the left-hand side value matches the right-hand side pattern.
        
        Args:
            lhs (str): The string to test.
            rhs (str): The pattern to match (supports wildcards).
        
        Returns:
            bool: True if the string matches the pattern, otherwise False.
        """
        logger.info("Checking like")
        return fnmatch.fnmatch(lhs, rhs)

    def between(self, lhs, rhs) -> bool:
        """
        Placeholder for a 'between' comparison operation.
        
        TODO: Implement comparison logic for ranges.
        """
        pass

    def from_date(self, lhs, rhs) -> bool:
        """
        Placeholder for a 'from_date' comparison operation.
        
        TODO: Implement comparison logic for dates.
        """
        pass

    def auth(self, resource):
        """
        Check if the resource's attribute satisfies the specification.
        
        Args:
            resource (Any): The resource to be evaluated.
        
        Returns:
            bool: True if authorized, False otherwise.
        """
        fetched_resource = fetch_resource("fetch_resource", resource)
        lhs = fetched_resource.get(self.attr, ...)
        if lhs is ...:
            return False
        rhs = self.from_value()
        return self.op(lhs, rhs)
    
    def __call__(self, resource) -> bool:
        """
        Allow the instance to be called directly to perform authorization.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if the resource is authorized, False otherwise.
        """
        return self.auth(resource)


class GMspec(ResourceSpec):
    """
    Resource specification for group-based permissions.
    
    Checks if a resource belongs to a given group, has a specific type, and meets capacity requirements.
    """

    def __init__(self, *, type, group, capacity):
        """
        Initialize a group-based resource specification.
        
        Args:
            type (str): Expected type of the resource.
            group (str): Group identifier the resource should belong to.
            capacity (Any): The capacity requirement for the resource.
        """
        self.type = type
        self.group = group
        self.capacity = capacity

    def check_group(self, resource):
        """
        Verify that the resource is associated with the specified group.
        
        Args:
            resource (str or dict): Resource identifier or resource data.
        
        Returns:
            bool: True if the resource is part of the group, otherwise False.
        """
        # When resource is provided as an ID (string), check against cached group members.
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
        """
        Verify that the resource type matches the expected type.
        
        Args:
            resource (Any): Resource identifier or resource data.
        
        Returns:
            bool: True if the type matches, otherwise False.
        """
        logger.info("Checking type")
        resource = fetch_resource("fetch_resource", resource)
        if resource.get("type", None) != self.type:
            return False
        return True

    def check_capacity(self, resource):
        """
        Verify that the resource meets the capacity requirement.
        
        Args:
            resource (str or dict): Resource identifier or resource data.
        
        Returns:
            bool: True if the capacity requirement is met, otherwise False.
        """
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
        """
        Authorize the resource based on group, type, and capacity.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if all checks pass, otherwise False.
        """
        if not self.check_group(resource):
            return False
        
        if not self.check_type(resource):
            return False
        
        if not self.check_capacity(resource):
            return False

        return True
    
    def __call__(self, resource) -> bool:
        """
        Allow the instance to be called directly for authorization.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if authorized, otherwise False.
        """
        return self.auth(resource)
    

class OMSpec(ResourceSpec):
    """
    Resource specification for organization-based permissions.
    
    Checks if a resource belongs to a given organization, has a specific type, and meets capacity requirements.
    """

    def __init__(self, *, type, org, capacity):
        """
        Initialize an organization-based resource specification.
        
        Args:
            type (str): Expected type of the resource.
            org (str): Organization identifier the resource should belong to.
            capacity (Any): The capacity requirement for the resource.
        """
        self.type = type
        self.org = org
        self.capacity = capacity

    def check_org(self, resource):
        """
        Verify that the resource is associated with the specified organization.
        
        Args:
            resource (str or dict): Resource identifier or resource data.
        
        Returns:
            bool: True if the resource is part of the organization, otherwise False.
        """
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
        """
        Verify that the resource type matches the expected type.
        
        Args:
            resource (Any): Resource identifier or resource data.
        
        Returns:
            bool: True if the type matches, otherwise False.
        """
        logger.info("Checking type")
        resource = fetch_resource("fetch_resource", resource)
        if resource.get("type", None) != self.type:
            return False
        return True

    def check_capacity(self, resource):
        """
        Verify that the resource meets the capacity requirement.
        
        Args:
            resource (str or dict): Resource identifier or resource data.
        
        Returns:
            bool: True if the capacity requirement is met, otherwise False.
        """
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
        """
        Authorize the resource based on organization, type, and capacity.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if all checks pass, otherwise False.
        """
        if not self.check_org(resource):
            return False
        
        if not self.check_type(resource):
            return False
        
        if not self.check_capacity(resource):
            return False

        return True
    
    def __call__(self, resource) -> bool:
        """
        Allow the instance to be called directly for authorization.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if authorized, otherwise False.
        """
        return self.auth(resource)


class UMspec(ResourceSpec):
    """
    Resource specification for user membership based permissions.
    
    Verifies that the current user is a member of a given group and meets the capacity requirements.
    """

    def __init__(self, *, group, capacity):
        """
        Initialize a user membership specification.
        
        Args:
            group (str): The group identifier.
            capacity (Any): The capacity requirement.
        """
        self.group = group
        self.capacity = capacity

    def check_group(self, resource):
        """
        Check if the current user is a member of the specified group.
        
        Args:
            resource (Any): Not used directly in this check.
        
        Returns:
            bool: True if the current user is in the group, otherwise False.
        """
        members = fetch_resource("fetch_group_members", self.group)
        user_info = ku.current_user()
        for member in members:
            if user_info["sub"] in member:
                return True
        return False
    
    def check_capacity(self, resource):
        """
        Check if the current user meets the capacity requirement within the group.
        
        Args:
            resource (Any): Not used directly in this check.
        
        Returns:
            bool: True if the user meets the capacity requirement, otherwise False.
        """
        members = fetch_resource("fetch_group_members", self.group)
        user_info = ku.current_user()
        for member in members:
            if user_info["sub"] in member and self.capacity in member:
                return True
        return False

    def auth(self, resource) -> bool:
        """
        Authorize the resource by checking the current user's group membership and capacity.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if the user is authorized, otherwise False.
        """
        if not self.check_group(resource):
            return False

        if not self.check_capacity(resource):
            return False

        return True
    
    def __call__(self, resource) -> bool:
        """
        Allow the instance to be called directly for authorization.
        
        Args:
            resource (Any): The resource to check.
        
        Returns:
            bool: True if authorized, otherwise False.
        """
        return self.auth(resource)


def fetch_resource(purpose, *args):
    """
    General-purpose function to retrieve resources or member lists from CKAN.
    
    Supports different purposes:
      - "fetch_resource": Retrieve a resource by its ID or return the provided resource.
      - "fetch_group_members": Retrieve members of a group (with caching via Flask.g).
      - "fetch_org_members": Retrieve members of an organization (with caching via Flask.g).
    
    Args:
        purpose (str): The type of resource to fetch.
        *args: Additional arguments depending on the purpose.
    
    Returns:
        Any: The fetched resource or member list.
    
    Raises:
        ValueError: If the group or organization does not exist.
    """
    logger.info("Now all calls the general purpose function")
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
    """
    Check if the user has access to perform a specified action on a resource.
    
    Iterates through the user's roles and checks if any role has permission,
    by evaluating all associated resource specification objects.
    
    Args:
        user_roles (list): List of roles associated with the user.
        action (str): The action to be performed (e.g., "read", "write").
        resource (Any): Resource identifier or resource data.
    
    Returns:
        bool: True if access is granted, otherwise False.
    """
    global action_permissions
    action_perms = action_permissions.get(action, {})

    # Check across all user roles for that specific action.
    for role_name in user_roles:
        
        role_perms = action_perms.get(role_name, [])
        logger.info(f"Role {role_name} has permissions {role_perms}")
        
        if role_perms and all(spec(resource) for spec in role_perms):
            logger.info("Access granted")
            return True  # Early exit if permission is granted.
    return False  # Deny access if no role grants permission.
