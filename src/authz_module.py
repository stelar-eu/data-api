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

import fnmatch
import logging
from abc import ABC, abstractmethod
from typing import Any
import uuid

import yaml
from flask import g


from data_module import DataModule
from exceptions import APIException, AuthorizationError
import kutils as ku
from backend.kc import KEYCLOAK_ADMIN_CLIENT
import monitor_module as mon
import mutils as mu
import reconciliation_module as rec
from entity import Entity, MemberEntity
import sql_utils

logger = logging.getLogger(__name__)

# Global dictionary to store permissions mapped by action.
action_permissions = {}
# Global dictionary to store new permissions during parsing(For reconciliation purposes).
new_permissions = {}
# Global list for maintaining the currently defined roles
role_names_list = []

role_names_list = []


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

    def alias_to_value(self, perm, alias, data):
        """
        Updates the 'perm' dictionary with an "action" key based on the alias lookup in data.

        Parameters:
            perm (dict): The permissions dictionary to update.
            alias (str): The alias key to look up in data.
            data (dict): A dictionary containing an "actions" sub-dictionary mapping aliases to values.

        Returns:
            dict: The updated perm dictionary.
        """
        actions = data.get("actions", {})
        if isinstance(alias, str):
            alias = [alias]

        actions_list = []
        for al in alias:
            alias_value = actions.get(al)

            # If no alias is found, return the original dictionary.
            if alias_value is None:
                return perm

            # If the alias value is a string, normalize to list.
            if isinstance(alias_value, str):
                alias_value = [alias_value]

            # Otherwise, assume alias_value is iterable (like a list) and build the actions list.
            for item in alias_value:
                if item in actions:
                    # Retrieve the value for the current item. If it's a string, wrap it in a list.
                    item_value = actions[item]
                    if isinstance(item_value, str):
                        item_value = [item_value]
                    actions_list.extend(item_value)
                else:
                    actions_list.append(item)

            perm["action"] = actions_list
        return perm

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
                        try:
                            print(yaml_content["actions"])
                            perm = self.alias_to_value(perm, a, yaml_content)
                        except Exception as e:
                            logger.error(
                                f"Error processing resourceType permissions: {e}"
                            )
                        resource_obj.create_permissions(role["name"], perm)
                    case {"action": a, "resource_spec": spec}:
                        logger.info("Processing resourceSpecType permissions")
                        perm = self.alias_to_value(perm, a, yaml_content)
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


class Resource:
    """
    Resource class to store the resource payload and entity type.
    """

    def __init__(self, payload, entity):
        self.payload = payload
        self.entity = entity


class ResourceSpecPermissionsType(AuthorizationModule):
    """
    Handles permissions defined with resource specifications ("resource_spec" in YAML).
    This class converts raw specifications into concrete resource specification objects.
    """

    def __init__(self):
        self.keycloak_admin = KEYCLOAK_ADMIN_CLIENT()
        # No initialization parameters required.

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
                return GMspec(type=t, group=g, capacity=c, is_org=False)
            case {"type": t, "org": o, "capacity": c}:
                return GMspec(type=t, group=o, capacity=c, is_org=True)
            case {"group": g, "capacity": c}:
                return UMspec(group=g, org=None, capacity=c)
            case {"org": o, "capacity": c}:
                return UMspec(group=None, org=o, capacity=c)
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
        global role_names_list
        logger.info("Creating resource_spec permissions")

        # create a realm role in Keycloak if not already exists

        ku.create_realm_role(self.keycloak_admin, role_name)
        if role_name not in role_names_list:
            role_names_list.append(role_name)

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
        self.keycloak_admin = KEYCLOAK_ADMIN_CLIENT()
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
        global role_names_list

        logger.info("Creating role dict")
        role_dict = {
            "name": role,
            "permissions": perm,
        }
        logger.info("Appending role dict to roles_list")
        self.roles_list.append(role_dict)
        if role not in role_names_list:
            role_names_list.append(role)

        if role not in role_names_list:
            role_names_list.append(role)

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
                    [
                        self.keycloak_admin.get_client_role(
                            self.client_id, client_role_name
                        )
                    ],
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
        global role_names_list

        existing_realm_roles = mon.get_current_realm_roles(self.keycloak_admin)
        existing_policies = mon.get_current_policies()
        existing_client_roles = mon.get_current_client_roles(self.keycloak_admin)

        roles_to_delete = rec.update_roles_from_yaml(
            role_names_list, existing_realm_roles
        )
        ku.delete_realm_roles(self.keycloak_admin, roles_to_delete)

        # Reset the global role_names_list to avoid duplicates in the next reconciliation.
        role_names_list = []

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
            resource (Resource): The resource to check against the specification.

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
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if authorized, False otherwise.
        """
        fetched_resource = fetch_resource(resource)
        lhs = fetched_resource.get(self.attr, ...)
        if lhs is ...:
            return False
        rhs = self.from_value()
        return self.op(lhs, rhs)

    def __call__(self, resource) -> bool:
        """
        Allow the instance to be called directly to perform authorization.

        Args:
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if the resource is authorized, False otherwise.
        """
        return self.auth(resource)


class GMspec(ResourceSpec):
    """
    Resource specification for group-based permissions.

    Checks if a resource belongs to a given group/organization, has a specific type, and meets capacity requirements.
    """

    def __init__(self, *, type, group, capacity, is_org):
        """
        Initialize a group-based resource specification.

        Args:
            type (str): Expected type of the resource.
            group (str): Group identifier the resource should belong to.
            capacity (Any): The capacity requirement for the resource.
            is_org (bool): True if the group is an organization, otherwise False.
        """
        self.type = type
        self.group = group
        self.capacity = capacity
        self.is_org = is_org

    def check_group(self, resource):
        """
        Verify that the resource is associated with the specified group/organization.

        Args:
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if the resource is part of the group, otherwise False.
        """
        # When resource is provided as an ID (string), check against cached group members.
        if isinstance(resource.payload, str):
            logger.info("Checking group with resource id")
            group_members = fetch_group_members(self.group, resource, self.is_org)
            for member in group_members:
                logger.info("Checking member")
                if resource.payload in member:
                    logger.info("Resource found in group")
                    return True
            return False
        else:
            groups = resource.payload.get("groups", None)
            if groups:
                for group in groups:
                    if group.get("name", None) == self.group:
                        return True
            return False

    def check_type(self, resource):
        """
        Verify that the resource type matches the expected type.

        Args:
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if the type matches, otherwise False.
        """
        logger.info("Checking type")
        resource = fetch_resource(resource)
        if resource.get("type", None) != self.type:
            return False
        return True

    def check_capacity(self, resource):
        """
        Verify that the resource meets the capacity requirement.

        Args:
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if the capacity requirement is met, otherwise False.
        """
        logger.info("Checking capacity")
        if isinstance(resource.payload, str):
            logger.info("Checking group for capacity")
            # group_members = fetch_resource("fetch_group_members", self.group, resource, self.is_org)
            group_members = fetch_group_members(self.group, resource, self.is_org)
            for member in group_members:
                logger.info("Checking member for capacity")
                if resource.payload in member and self.capacity in member:
                    return True
            return False
        return False

    def auth(self, resource) -> bool:
        """
        Authorize the resource based on group, type, and capacity.

        Args:
            resource (Resource): Resource object containing the resource's payload and the resource's type.

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
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if authorized, otherwise False.
        """
        return self.auth(resource)


class UMspec(ResourceSpec):
    """
    Resource specification for user membership based permissions.

    Verifies that the current user is a member of a given group/organization and meets the capacity requirements.
    """

    def __init__(self, *, group: None, org: None, capacity):
        """
        Initialize a user membership specification.

        Args:
            group (str): The group identifier.
            org (str): The organization identifier.
            capacity (Any): The capacity requirement.

        """
        self.org = org
        self.group = group
        self.capacity = capacity
        self.is_org = False

        # Determine if the group is an organization.
        if self.group is None and self.org:
            self.is_org = True

    def check_group(self, resource):
        """
        Check if the current user is a member of the specified group/organization.

        Args:
            resource (Resource): Not used directly in this check.

        Returns:
            bool: True if the current user is in the group/organization, otherwise False.
        """
        # if is_org is true then fetch the organization members else fetch the group members
        if self.is_org:
            members = fetch_user_group_members(self.org, self.is_org)
        else:
            members = fetch_user_group_members(self.group, self.is_org)

        user_info = ku.current_user()
        for member in members:
            if user_info["sub"] in member:
                return True
        return False

    def check_capacity(self, resource):
        """
        Check if the current user meets the capacity requirement within the group/organization.

        Args:
            resource (Resource): Not used directly in this check.

        Returns:
            bool: True if the user meets the capacity requirement, otherwise False.
        """
        if self.is_org:
            members = fetch_user_group_members(self.org, self.is_org)
        else:
            members = fetch_user_group_members(self.group, self.is_org)

        user_info = ku.current_user()
        for member in members:
            if user_info["sub"] in member and self.capacity in member:
                return True
        return False

    def auth(self, resource) -> bool:
        """
        Authorize the resource by checking the current user's group/organization membership and capacity.

        Args:
            resource (Resource): Resource object containing the resource's payload and the resource's type.

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
            resource (Resource): Resource object containing the resource's payload and the resource's type.

        Returns:
            bool: True if authorized, otherwise False.
        """
        return self.auth(resource)


def fetch_group_members(group, resource, is_org):
    """
    Retrieve members of a group from the catalogue.

    Args:
        group (str): The group identifier.
        resource (Resource): Resource object containing the resource's payload and the resource's type.
        is_org (bool): True if the group is an organization, otherwise False.

    Returns:
        list: List of members in the group.

    """
    if not hasattr(g, "ckan_group_members"):
        g.ckan_group_members = {}
    if group in g.ckan_group_members:
        logger.info("Group members retrieved from flask.g cache")
        return g.ckan_group_members[group]
    try:
        if is_org:
            members = MemberEntity.REGISTRY[
                (resource.entity, "organization")
            ].list_members(eid=group)
        else:
            logger.info("entity is: " + resource.entity)
            logger.info("group is: " + group)
            members = MemberEntity.REGISTRY[(resource.entity, "group")].list_members(
                eid=group
            )
    except Exception:
        raise ValueError("Group does not exist")
    g.ckan_group_members[group] = members
    return members


def fetch_user_group_members(group, is_org):
    """
    Retrieve user members of a group from the catalogue.

    Args:
        group (str): The group identifier.
        is_org (bool): True if the group is an organization, otherwise False.

    Returns:
        list: List of user members in the group.

    """
    if not hasattr(g, "ckan_user_group_members"):
        g.ckan_user_group_members = {}
    if group in g.ckan_user_group_members:
        logger.info("User Group members retrieved from flask.g cache")
        return g.ckan_user_group_members[group]
    try:
        if is_org:
            user_members = MemberEntity.REGISTRY[("user", "organization")].list_members(
                eid=group
            )
        else:
            user_members = MemberEntity.REGISTRY[("user", "group")].list_members(
                eid=group
            )
    except Exception:
        raise ValueError("Group does not exist")
    g.ckan_user_group_members[group] = user_members
    return user_members


def fetch_resource(resource) -> dict:
    """
    Retrive the resource from the catalogue.

    Args:
        resource (Resource): Resource object containing the resource's payload and the resource's type.

    Returns:
        dict: The fetched resource.

    """
    if not isinstance(resource.payload, dict):
        fetched = Entity.REGISTRY[resource.entity].get_cached(resource.payload)
        logger.info("Resource %s fetched: %s", resource.payload, fetched)
        return fetched
    else:
        return resource.payload


def check_read_access_for_packages(package, current_user) -> list:
    """
    Checks if the requested package is accessible to the current user.
    if the package is private, it checks if the user is a member of the organization.
    if the package is public, it returns True.
    Args:
        package (str): The package identifier.

    Returns:
        bool: True if the package is accessible, otherwise False.
    """
    if package is None:
        return None

    if package.get("private"):
        logger.info("Package is private, checking access")
        organization = package.get("owner_org")

        user_members = fetch_user_group_members(organization, True)
        logger.info("User members: %s", user_members)
        logger.info("Current user: %s", current_user["sub"])
        for member in user_members:
            if current_user["sub"] in member:
                return True

        raise AuthorizationError(
            message="Error: You do not have access to this package",
        )
    else:
        logger.info("Package is public, access granted")
        return True


def check_read_access_for_resources(resource, current_user) -> list:
    """
    Checks if the requested resource is accessible to the current user.
    If the resource belongs to a package that the current user has access to, it returns True.
    Args:
        resource (str): The resource identifier.
        current_user (str): The current user identifier.
    Returns:
        bool: True if the resource is accessible, otherwise False.
    """
    if resource is None:
        return None
    logger.info("Resource: %s", resource)
    # Check if the resource belongs to a package that the user has access to
    for entity in ["dataset", "workflow", "process", "tool"]:
        try:
            package = Entity.REGISTRY[entity].get_cached(resource.get("package_id"))
        except Exception:
            logger.info("Error fetching package: %s", resource.get("package_id"))
            continue

    logger.info("Package: %s", package)
    if package is None:
        return None

    return check_read_access_for_packages(package, current_user)


def check_accessible_packages(fq):
    """
    Checks the accessible packages from the user.
    This function is used to filter the packages in the search.
    Args:
        fq (str): The filter query string.
    Returns:
        fq: The updated filter query string including the permission labels
        that solr should use to filter the packages.

    """
    fq = [f for f in fq if "permission_labels" not in f]

    fq_org_parts = []
    user_info = ku.current_user()
    organizations_of_user = sql_utils.get_user_organizations(user_info["sub"])

    for org in organizations_of_user:
        fq_org_parts.append(f" member-{org}")

    # Construct Solr `fq` string with ORs only between entries
    if fq_org_parts:
        fq_query = (
            "permission_labels:(capacity:public OR" + " OR ".join(fq_org_parts) + ")"
        )
        fq.append(fq_query)
    else:
        fq_query = "permission_labels:(capacity:public)"
        fq.append(fq_query)

    return fq


def check_access(user_roles, action, resource):
    """
    Check if the user has access to perform a specified action on a resource.

    Iterates through the user's roles and checks if any role has permission,
    by evaluating all associated resource specification objects.

    Args:
        user_roles (list): List of roles associated with the user.
        action (str): The action to be performed (e.g., "read", "write").
        resource (Resource): Resource object containing the resource's payload and the resource's type.

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


def authorization(resource: Resource, action: str) -> bool:
    """
    This function is the entry point for the authorization process.

    args:
        resource (Resource): Resource object containing the resource's payload and the resource's type.
        action: The action to be performed on the resource.

    returns:
        bool: True if the user has access, otherwise False.
    """

    # fetch the cuurent user info and roles
    user_info = ku.current_user()
    if hasattr(g, "user_roles"):
        user_roles = g.user_roles
    else:
        user_roles = ku.get_user_roles(user_info["sub"])
        g.user_roles = user_roles

    logger.info(f"Checking access for user {user_info['sub']} with roles {user_roles}")

    return check_access(user_roles, action, resource)


#################################################################################################################
# The following functions are used to create, retrieve, and manage authorization policies in the database.      #
# These functions interact with the SQL database to store and retrieve policy representations.                  #
#################################################################################################################


def create_authorization_schema(config_data):
    """
    Create the authorization schema for the application.

    This function initializes the authorization module and sets up the necessary
    configurations for role-based access control.
    Args:
        config_data (str): YAML configuration string defining roles and permissions.
    Returns:
        dict: The parsed YAML configuration.
    Raises:
        APIException: If the policy cannot be stored in the database.
    """

    yaml_str = config_data
    yaml_content = AuthorizationModule(config=config_data)()
    DataModule(config=config_data)
    ####################################################################################
    ########################## store policy file to db #################################
    logger.info(f"store policy file to db")
    policy_id = str(uuid.uuid4())
    # user_id = ""

    user = ku.current_user()
    if user:
        user_id = user.get("username")

    if sql_utils.policy_version_create(
        policy_id, "Not specified", True, str(yaml_str), user_id
    ):
        return yaml_content
    else:
        raise APIException(
            status_code=500,
            message="Error: The new policy was not stored in the database",
        )


def retrieve_policy_from_db(policy_uuid):
    """
    Retrieve the policy representation from the database.
    This function fetches the policy representation from the database
    and formats it into a YAML string.
    Args:
        policy_uuid (str): The UUID of the policy to retrieve.
    Returns:
        str: The formatted YAML string representation of the policy.
    Raises:
        APIException: If the policy is not found in the database.
    """

    policy_repr = sql_utils.policy_representation_read(policy_uuid)

    if policy_repr is None:
        raise APIException(
            status_code=404,
            message="Error: The policy was not found in the database",
        )

    # Decode the policy representation from bytes to string
    if policy_repr.startswith("b'"):
        policy_repr = policy_repr[2:-1]

    # Convert the policy representation to a YAML string
    formatted_yaml_string = policy_repr.encode("utf-8").decode("unicode_escape")

    return formatted_yaml_string


def retrieve_policy_info_from_db(policy_uuid):
    """
    Retrieve the policy information from the database.
    This function fetches the policy information from the database
    and returns it as a dictionary.
    Args:
        policy_uuid (str): The UUID of the policy to retrieve.
    Returns:
        dict: The policy information as a dictionary.
    Raises:
        APIException: If the policy info not found in the database.
    """

    policy_repr = sql_utils.policy_info_read(policy_uuid)

    if policy_repr is None:
        raise APIException(
            status_code=404,
            message="Error: The policy info was not found in the database",
        )

    return policy_repr


def retrieve_policies_list_from_db():
    """
    Retrieve the list of policies from the database.
    This function fetches the list of all policies from the database
    and returns it as a list of dictionaries.
    Returns:
        list: The list of policies.
    Raises:
        APIException: If the policies could not be fetched.
    """

    policies_list = sql_utils.list_policies()

    if policies_list is None:
        raise APIException(
            status_code=500,
            message="Error: Could not fetch policies from db",
        )
    policies_dict = {"policies": policies_list}

    return policies_dict


def load_authorization_schema():
    """
    Load the authorization schema from the database.
    This function retrieves the last active policy from the database
    and initializes the authorization module with it.
    """
    config_file = retrieve_policy_from_db("active")

    if config_file:
        yaml_content = AuthorizationModule(config=config_file)()

    logger.info("Loading authorization schema %s", yaml_content)
