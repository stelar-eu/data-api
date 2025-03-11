"""
Contains the Entity class and its subclasses. 

The Entity class is a base class for STELAR entities. The main responsibility
of the Entity class is to provide a common interface for interacting via the
STELAR API. The class defines a set of operations that can be performed 
on an entity, such as listing, fetching, creating, updating, and deleting. 
The specific implementation of these operations is left to the subclasses. 


CKAN-based entities:
--------------------

The main subclass of Entity is the CKANEntity class, which is used to handle
entities that are stored in CKAN.

The CKANEntity class provides methods to interact with CKAN and to perform CRUD
operations on the entities. The subclasses of CKANEntity are used to customize
specific CKAN entities, such as datasets, groups, and organizations. The subclasses
define the specific attributes and methods for each entity sub-type.

In particular, the EntityWithMembers class is used to handle CKAN entities that
have members, that is, groups and organizations. It provides methods to add, 
remove, and list members of the group or organization. The MemberEntity class is 
used to customize the membership API in entities with members.

Also, the EntityWithExtras class is used to handle CKAN entities that have extras,
that is, additional attributes stored in the 'extras' field in CKAN. The 
EntityWithExtrasCKANSchema class is used to define the schema for entities with
extras in CKAN.

The PackageEntity class is used to handle CKAN entities based on packages, such
as datasets, processes, workflows, and tools. It provides methods to filter packages
by type and to create, update, and delete packages.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from apiflask import Schema, fields, validators
from marshmallow import EXCLUDE, SchemaOpts, missing, post_dump, pre_load
from psycopg2 import sql

import schema
from backend.ckan import ckan_request, filter_list_by_type
from backend.pgsql import execSql, transaction
from exceptions import BackendLogicError, DataError, InternalException, NotFoundError
from search import entity_search
from tags import tag_object_to_string, tag_string_to_object

logger = logging.getLogger(__name__)


class Entity:
    """Base class for all API entities.

    In ReST terminology, an entity is a resource that can be accessed via an API.

    This class provides the basic structure for all entities. It defines the common
    operations that can be performed on an entity, such as listing, fetching, creating,
    updating, and deleting. The specific implementation of these operations is left to
    the subclasses.

    The API defined in this class is the one used by the generic endpoint definitions.

    The generic endpoint definitions use the API defined in the Entity class to implement
    the CRUD operations for the entities. For this purpose, each Entity defines four fields:

    - name: the name of the entity
    - collection_name: the name of the collection of entities
    - creation_schema: the schema for creating entities
    - update_schema: the schema for updating entities
    """

    OPERATIONS = [
        "list",
        "fetch",
        "search",
        "show",
        "create",
        "delete",
        "update",
        "patch",
    ]

    def __init__(
        self,
        name: str,
        collection_name: str,
        creation_schema: Schema,
        update_schema: Schema,
    ):
        """Initialize the entity.

        Args:
            name: The name of the entity.
            collection_name : The name of the collection of entities.
            creation_schema: The schema for creating entities.
            update_schema: The schema for updating entities. If None, the entity does not support updates.
        """
        self.name = name
        self.collection_name = collection_name

        self.creation_schema = creation_schema
        self.update_schema = update_schema

        # Store the endpoint functions
        self.operations = Entity.OPERATIONS.copy()
        self.operations.remove("search")
        if update_schema is None:
            self.operations.remove("update")
            self.operations.remove("patch")

        self.endpoints = {}
        logger.info("Instantiated entity %s", self.name)

    def list_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        """List the entities of this type.

        This method is used to list the entities of this type. It returns a list of entity IDs.

        Args:
            limit: The maximum number of entities to return.
            offset: The offset to start listing entities from.
        Returns:
            A list of entity IDs.
        """
        return self.list(limit=limit, offset=offset)

    def fetch_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        """Fetch the entities of this type.

        This method is used to fetch the entities of this type. It returns a list of entity objects.

        Args:
            limit: The maximum number of entities to return.
            offset: The offset to start fetching entities from.
        Returns:
            A list of entity objects.
        """
        return self.fetch(limit=limit, offset=offset)

    def search_entities(self, query_spec: dict) -> list:
        """Search for entities of this type.

        This method is used to search for entities of this type. It returns a list of entity objects.

        Args:
            query_spec: The query specification. This is a dict validated by `schema.EntitySearchQyery`
        Returns:
            A list of entity objects.
        """
        return self.search(query_spec)

    def get_entity(self, eid: str):
        """Get an entity by ID.

        This method is used to get an entity by its ID.

        Args:
            eid: The ID of the entity to get.
        Returns:
            The entity object.
        """
        return self.get(eid)

    def create_entity(self, init_data):
        """Create a new entity.

        This method is used to create a new entity.

        Args:
            init_data: The data to initialize the entity with.
        Returns:
            The created entity object.
        """
        return self.create(init_data)

    def delete_entity(self, eid: str, purge=False):
        """Delete an entity.

        This method is used to delete an entity.

        Args:
            eid: The ID of the entity to delete.
            purge: Whether to purge the entity.
        Returns:
            The result of the delete operation.
        """
        return self.delete(eid, purge)

    def update_entity(self, eid: str, entity_data):
        """Update an entity.

        This method is used to update an entity. It performs a full update,
        replacing the entity with the new data. If attributes are missing in
        the new data, they will be removed from the entity (if applicable).

        Args:
            eid: The ID of the entity to update.
            entity_data: The data to update the entity with.
        Returns:
            The updated entity object.
        """
        return self.update(eid, entity_data)

    def patch_entity(self, eid: str, patch_data):
        """Patch an entity.

        This method is used to patch an entity. It performs a partial update,
        updating only the attributes present in the patch data. If attributes
        are missing in the patch data, they will be left unchanged.

        Args:
            eid: The ID of the entity to patch.
            patch_data: The data to patch the entity with.
        Returns:
            The patched entity object.
        """
        return self.patch(eid, patch_data)

    #
    # The following methods are the actual implementations of the API
    # operations, bypassing any authorization checks.
    #

    def list(self, limit: Optional[int] = None, offset: Optional[int] = None):
        raise NotImplementedError

    def fetch(self, limit: Optional[int] = None, offset: Optional[int] = None):
        raise NotImplementedError

    def get(self, eid: str):
        raise NotImplementedError

    def create(self, init_data):
        raise NotImplementedError

    def delete(self, eid: str, purge=False):
        raise NotImplementedError

    def update(self, eid: str, entity_data):
        raise NotImplementedError

    def patch(self, eid: str, patch_data):
        raise NotImplementedError


class CKANEntity(Entity):
    def __init__(
        self,
        *args,
        ckan_name: str,
        ckan_schema: Schema,
        **kwargs,
    ):
        """Initialize a CKAN entity.

        Args:
            ckan_name: The name of the entity in CKAN.
            ckan_schema: The schema for the entity in CKAN, used to convert data to and from CKAN format.
        """

        super().__init__(*args, **kwargs)

        self.ckan_name = ckan_name if ckan_name is not None else self.name
        self.ckan_api_list = f"{self.ckan_name}_list"
        self.ckan_api_show = f"{self.ckan_name}_show"
        self.ckan_api_create = f"{self.ckan_name}_create"
        self.ckan_api_delete = f"{self.ckan_name}_delete"
        self.ckan_api_purge = f"{self.ckan_name}_purge"
        self.ckan_api_update = f"{self.ckan_name}_update"
        self.ckan_api_patch = f"{self.ckan_name}_patch"

        if isinstance(ckan_schema, type):
            self.ckan_schema = ckan_schema()
        else:
            # Note: it is ok for ckan_schema to be None
            self.ckan_schema = ckan_schema

        self.has_extras = False

        # Only packages have tags!
        self.has_tags = self.ckan_name == "package"

    def create_to_ckan(self, init_data):
        """Convert the data to the CKAN format.

        The CKAN format is a JSON object with the fields in the correct format
        for the CKAN API creation operation.

        Conversion is done under the guidance of the CKAN schema of this entity.

        Args:
            init_data: The data to convert.
        Returns:
            The data in the CKAN format.
        """
        init_data = self.ckan_schema.dump(init_data)
        return init_data

    def update_to_ckan(self, update_data, current_obj):
        """Convert the data to the CKAN format for updating.

        This method is used to convert the update data to the CKAN format for updating
        an existing entity. It may need to fetch the current object from the database
        to properly merge the update data.

        Args:
            update_data: The data to convert.
            current_obj: The current object in the database, or None if not available.
        """
        update_data = self.ckan_schema.dump(update_data)
        return update_data

    def load_from_ckan(self, ci):
        """Convert the data from the CKAN format.

        Args:
            ci: The data to convert.
        Returns:
            The converted data object.
        """
        ci = self.ckan_schema.load(ci)
        return ci

    @staticmethod
    def check_limit_offset(val, name):
        if not isinstance(val, Optional[int]):
            raise DataError(f"{name} must be an integer, or None")
        if val is not None:
            if val < 0:
                raise DataError(f"{name} must be nonnegative")

    def list(self, limit: Optional[int] = None, offset: Optional[int] = None):
        """List the entities of this type.

        Args:
            limit: The maximum number of entities to return.
            offset: The offset to start listing entities from.
        Returns:
            A list of entity IDs.
        """
        self.check_limit_offset(limit, "limit")
        self.check_limit_offset(offset, "offset")
        return ckan_request(self.ckan_api_list, limit=limit, offset=offset)

    def fetch(self, limit: Optional[int] = None, offset: Optional[int] = None):
        """Fetch the entities of this type.

        Args:
            limit: The maximum number of entities to return.
            offset: The offset to start fetching entities from.
        Returns:
            A list of entity objects.
        """
        entids = self.list_entities(limit=limit, offset=offset)
        ents = []
        for eid in entids:
            e = self.get_entity(eid)
            ents.append(e)
        return ents

    def get(self, eid: str):
        """Read an entity from CKAN.

        This method bypasses any authorization checks.

        Args:
            eid: The ID of the entity to read.
        Returns:
            The entity object.
        """
        obj = ckan_request(self.ckan_api_show, id=eid, context={"entity": self.name})
        # Check the type of the CKAN object (for those CKAN objects that have type)
        objtype = obj.get("type", self.name)
        if objtype != self.name:
            raise NotFoundError(f"{self.name} not found, ID belongs to {objtype}")
        return self.load_from_ckan(obj)

    def create(self, init_data):
        """Create an entity in CKAN.

        Args:
            init_data: The data to create the entity with.
        Returns:
            The created entity object.
        """
        context = {"entity": self.name}

        ckinit_data = self.create_to_ckan(init_data)

        obj = ckan_request(self.ckan_api_create, context=context, json=ckinit_data)
        logger.info("Created %s id=%s", self.name, obj["id"])
        return self.load_from_ckan(obj)

    def delete(self, eid: str, purge=False):
        """Delete an entity from CKAN.

        Args:
            eid: The ID of the entity to delete.
            purge: Whether to purge the entity.
        Returns:
            The result of the delete operation in CKAN, if any.
        """
        ckan_cmd = self.ckan_api_purge if purge else self.ckan_api_delete
        context = {"entity": self.name}
        result = ckan_request(ckan_cmd, id=eid, context=context)
        logger.info("%s %s id=%s", "Purged" if purge else "Deleted", self.name, eid)
        return result

    def update(self, eid: str, entity_data):
        """Update an entity in CKAN.

        Args:
            eid: The ID of the entity to update.
            entity_data: The data to update the entity with.
        Returns:
            The updated entity object.
        """
        context = {"entity": self.name}

        # Convert to CKAN properly
        ck_data = self.update_to_ckan(entity_data, eid)

        obj = ckan_request(self.ckan_api_update, id=eid, context=context, json=ck_data)
        return self.load_from_ckan(obj)

    def patch(self, eid: str, patch_data):
        """Patch an entity in CKAN.

        Args:
            eid: The ID of the entity to patch.
            patch_data: The data to patch the entity with.
        Returns:
            The patched entity object.
        """
        context = {"entity": self.name}

        ckpatch_data = self.update_to_ckan(patch_data, eid)

        obj = ckan_request(
            self.ckan_api_patch, id=eid, context=context, json=ckpatch_data
        )
        return self.load_from_ckan(obj)


def create_capacity_schema(
    name, capacities: re.Pattern | list[str] | None
) -> schema.Schema:
    """Create a schema for a capacity field.

    This function creates a schema for a capacity field, which is used to specify the role
    of a member in a group or organization. The schema can be customized to accept specific
    values or patterns for the capacity field.

    Args:
        name: The name of the schema.
        capacities: The valid values or pattern for the capacity field.
    Returns:
        The capacity schema.
    """

    if isinstance(capacities, list):
        if capacities == []:
            logger.critical("Empty list of capacities")
            raise ValueError("Empty list of capacities")
        val = validators.OneOf(capacities)
        capdoc = "Valid capacities are: " + ", ".join(capacities)

    elif capacities is None:
        val = validators.Length(min=2, max=100)
        capdoc = "Any string can be used for capacity, as long as its length is between 2 and 100 characters"

    elif isinstance(capacities, re.Pattern):
        val = validators.Regexp(capacities)
        capdoc = f"The capacity must match the regular expression: {capacities.pattern}"
    else:
        logger.critical(f"Invalid capacities for {name}: {capacities}")
        raise ValueError(f"Invalid capacities: {capacities}")

    class AddMember(Schema):
        capacity = fields.String(validate=[val])

    AddMember.__name__ = name
    AddMember.__qualname__ = name
    AddMember.capdoc = capdoc

    return AddMember


AnyCapacity = create_capacity_schema("AnyCapacity", re.compile(r"[\w\d_]*"))
UserGroupCapacity = create_capacity_schema("UserGroupCapacity", ["editor", "member"])
UserOrgCapacity = create_capacity_schema(
    "UserOrgCapacity", ["admin", "editor", "member"]
)


def db_fetch_entity_extras(eid: str, table: str):
    """Fetch the extras for an entity from the database.

    Arguments:
        eid: the ID of the entity
        table: the name of the table to fetch from. This should be
            either 'package' or 'group'
    Returns:
        a dictionary with all the extras
    """
    with transaction() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("SELECT key, value FROM {table} WHERE {eid} = %s").format(
                    table=sql.Identifier(f"{table}_extra"),
                    eid=sql.Identifier(f"{table}_id"),
                ),
                [eid],
            )
            extras = {row[0]: row[1] for row in cur}
    return extras


class EntityWithExtras(CKANEntity):
    """This class treats CKAN entities which have extras.

    This includes package-derived entities, and group-derived entities.
    Such entities are allowed to have additional attributes, defined at
    the schema level, but saved in the 'extras' field in CKAN.

    This class encapsulates the logic for handling these additional
    attributes. In particular, it provides methods to fold and unfold
    these attributes into the 'extras' field when saving and loading.
    """

    def __init__(self, *args, extras_table: str, **kwargs):
        """Initialize the entity with extras.

        Args:
            extras_table: the name of the table where the extras are stored. This is either
                'package' or 'group'.
        """

        super().__init__(*args, **kwargs)

        self.has_extras = True
        self.extras_table = extras_table

    def update_to_ckan(self, update_data, current_obj):
        """Convert the data to the CKAN format for updating.

        This method is overloaded to handle the 'extras' field, supporting
        entities implemented by the 'package' or 'group' in CKAN.
        Instances may declare attributes that are actually stored in the CKAN
        'extras' field.

        When updating such entities, we need to merge the update spec with
        the current CKAN-stored extras. This method helps in this process
        by providing the full 'extras' object for proper merging later on
        by the ckan_schema.dump() method.
        """

        if self.ckan_schema.opts.extra_attributes:
            extras_present = "extras" in update_data

            if extras_present or any(
                attr in update_data for attr in self.ckan_schema.opts.extra_attributes
            ):
                # Fetch the full 'extras' object directly from the database
                curextras = db_fetch_entity_extras(current_obj, self.extras_table)

                # Add the curextras object to the update data
                update_extras = update_data.setdefault("extras", {})
                # Note that we are purposely using a name with spaces...
                update_extras["current extras object"] = curextras
                update_extras["extras update present"] = extras_present

        update_data = self.ckan_schema.dump(update_data)
        return update_data

    def create_to_ckan(self, init_data):
        """Transform data to CKAN format for creation requests.

        When creating, if we have extras-based attributes, we need to
        provide values so that they can be put in the extras field.
        This is the load_default, or, if allow_none, it is none.
        """

        for attr in self.ckan_schema.opts.extra_attributes:
            if attr in init_data:
                continue

            field = self.ckan_schema.fields[attr]
            load_default = field.load_default

            if load_default is not missing:
                init_data[attr] = load_default
            elif field.allow_none:
                init_data[attr] = None
            else:
                raise BackendLogicError(
                    f"Attribute {attr} is required on create, for {self.name}"
                )

        return super().create_to_ckan(init_data)


class CKANEntityOptions(SchemaOpts):
    def __init__(self, meta, **kwargs):
        super().__init__(meta, **kwargs)
        self.extra_attributes = getattr(meta, "extra_attributes", [])
        self.extra_attributes_raw = getattr(meta, "extra_attributes_raw", [])
        if any(a not in self.extra_attributes for a in self.extra_attributes_raw):
            raise ValueError(
                "extra_attributes_raw must be a subset of extra_attributes"
            )


class EntityWithExtrasCKANSchema(Schema):
    """The back-end (CKAN) schema for entities with extras.

    This schema is used as a base class to handle additional attributes.
    """

    OPTIONS_CLASS = CKANEntityOptions

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    # -------------------------------------------------------
    # The 'extras' field is a dictionary of key-value pairs.
    # We declare it here; subclasses should not declare it.
    #

    extras = fields.Raw()

    #
    # -------------------------------------------------------

    def unfold_fields(self, data: dict):
        """This method is called at loading (from CKAN) to unfold the
        named extra fields from the 'extras' field.
        """

        # This will raise if the 'extras' field is not present, but that's ok...
        extras = data["extras"]

        if self.opts.extra_attributes:
            for attr in self.opts.extra_attributes:
                if attr in extras:
                    data[attr] = extras.pop(attr)

    @staticmethod
    def jsload(value):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    @pre_load
    def load_extras(self, data, **kwargs):
        # Process the extras
        extras = data.get("extras", [])
        data_extras = {}
        for e in extras:
            k, v = e["key"], e["value"]
            if k not in self.opts.extra_attributes_raw:
                v = self.jsload(v)
            data_extras[k] = v

        data["extras"] = data_extras
        # Unfold the extra attributes
        self.unfold_fields(data)
        # Return the data to be loaded
        return data

    #
    #  Dump extras to CKAN with extras-based attribute folding.
    #

    def fold_fields(self, data: dict):
        """This method is called at dumping (to CKAN) to fold named
        extra fields into the 'extras' field.

        To be able to merge everything properly, we need to dump everything
        to string here.
        """

        extras = data.get("extras", None)
        attrs = {}
        for attr in self.opts.extra_attributes:
            if attr in data:
                if attr in self.opts.extra_attributes_raw:
                    if not isinstance(data[attr], str | None):
                        raise InternalException(
                            f"Raw attribute {attr} must be a string or None at folding time"
                        )
                    attrs[attr] = data[attr]
                else:
                    attrs[attr] = json.dumps(data[attr])

        if (not attrs) and extras is None:
            return

        if extras is None:
            extras = {}

        # We could have an 'instrumented' extras object
        if "current extras object" in extras:
            current_extras = extras.pop("current extras object")
            extras_present = extras.pop("extras update present")

            # Before merge, we convert dump the remaining extras
            extras = {k: json.dumps(v) for k, v in extras.items()}

            # Merge the current extras with the new extras
            if extras_present:
                curattrs = {
                    attr: current_extras[attr]
                    for attr in self.opts.extra_attributes
                    if attr in current_extras
                }
                extras = extras | (curattrs | attrs)
            else:
                extras = current_extras | attrs
        else:
            # Convert the extras to strings
            extras = {k: json.dumps(v) for k, v in extras.items()}

            extras |= attrs

        data["extras"] = extras

    @post_dump
    def dump_extras(self, data, **kwargs):
        # Process the extra attributes folding them into the extras field
        self.fold_fields(data)

        # Serialize the extras (if any!).
        extras = data.get("extras", None)
        if extras is not None:
            # Attributes have already been serialized to json, now turn them
            # into strings.

            data["extras"] = [{"key": k, "value": v} for k, v in extras.items()]
        # Ready to dump to CKAN
        return data


class MemberEntity:
    """This class customizes membership in entities with members.

    Arguments:
        name: the name of the member (e.g. 'dataset', 'group')
        ckan_type:
    """

    OPERATIONS = ["add_member", "remove_member", "list_members"]

    def __init__(
        self,
        parent: Entity,
        child: Entity,
        capacity_schema: Optional[schema.Schema],
    ):
        self.parent = parent
        self.child = child
        self.member_kind = child.ckan_name
        self.capacity_schema = capacity_schema
        self.operations = MemberEntity.OPERATIONS
        if parent:
            parent.members.append(self)
        self.endpoints = {}

    def add_member_entity(self, eid: str, member_id: str, capacity: str):
        """Add a member to a group or org.

        This method performs authorization checks and then calls the
        add_member() method.

        Arguments:
            eid: the ID of the group or org
            member_id: the ID of the member
            capacity: the capacity of the member
        """
        return self.add_member(eid, member_id, capacity)

    def remove_member_entity(self, eid: str, member_id: str):
        """Remove a member from a group or org.

        This method performs authorization checks and then calls the
        remove_member() method.

        Arguments:
            eid: the ID of the group or org
            member_id: the ID of the member
        """
        return self.remove_member(eid, member_id)

    def list_member_entities(self, eid: str, capacity: str | None = None):
        """List the members of a group or org.

        This method performs authorization checks and then calls the
        list_members() method.

        Arguments:
            eid: the ID of the group or org
            capacity: the capacity of the members to list, or None to list all members.
        """
        return self.list_members(eid, capacity)

    def add_member(self, eid: str, member_id: str, capacity: str):
        context = {"member_entity": self.child.name}
        self.parent.add_member(
            eid, member_id, self.member_kind, capacity=capacity, context=context
        )

    def remove_member(self, eid: str, member_id: str):
        context = {"member_entity": self.child.name}
        self.parent.remove_member(eid, member_id, self.member_kind, context=context)

    def list_members(self, eid: str, capacity: str | None = None) -> list[dict]:
        context = {"member_entity": self.child.name}

        # Get the list of members from the parent entity
        mlist = self.parent.list_members(
            eid, self.member_kind, capacity=capacity, context=context
        )

        if self.member_kind == "package":
            # Filter the list of members by type
            idlist = [m[0] for m in mlist]
            pkg_type = self.child.package_type
            flist = filter_list_by_type(idlist, pkg_type)
            fset = set(flist)

            return [[m[0], pkg_type, m[2]] for m in mlist if m[0] in fset]

        else:
            return mlist


class EntityWithMembers(EntityWithExtras):
    """This class treats CKAN entities which have members.

    This includes groups and organizations as well as any custom types derived
    from them (organizations are already a type of group).
    """

    def __init__(self, *args, members: list[MemberEntity] = [], **kwargs):
        super().__init__(*args, extras_table="group", **kwargs)
        self.members = members
        for m in self.members:
            m.parent = self

    def get(self, eid: str):
        #
        # Because of a bug in CKAN code, getting CKAN groups and orgs fails (CKAN returns 'internal error')
        # when there are cycles between groups. To ameliorate this, we need to pass the 'include_groups=False'
        # flag.
        #
        # FYI: the bug is in file './ckan/lib/dictization/model_dictize.py' and manifests as a "stack overflow"
        # (in python the exception is "Recursion Depth exceeded").
        #
        obj = ckan_request(
            self.ckan_api_show,
            id=eid,
            # the line below fixes the bug mentioned above
            include_groups=False,
            # Exclude tags, since they are not actually supported
            # Also, exclude some irrelevant stuff
            include_tags=False,
            include_followers=False,
            include_users=False,
            include_datasets=False,
            include_dataset_count=False,
            # INCLUDE the extras!
            include_extras=True,
            context={"entity": self.name},
        )
        return self.load_from_ckan(obj)

    #
    # Raw members calling CKAN
    #
    def add_member(
        self,
        eid: str,
        member_id: str,
        member_kind: str,
        capacity: str,
        context: dict = {},
    ):
        context = {"entity": self.name}
        obj = ckan_request(
            "member_create",
            id=eid,
            object=member_id,
            object_type=member_kind,
            capacity=capacity,
            context=context,
        )

    def remove_member(
        self, eid: str, member_id: str, member_kind: str, context: dict = {}
    ):
        context = {"entity": self.name}
        ckan_request(
            "member_delete",
            id=eid,
            object=member_id,
            object_type=member_kind,
            context=context,
        )

    def list_members(
        self,
        eid: str,
        member_kind: str | None = None,
        capacity: str | None = None,
        context: dict = {},
    ) -> list[dict]:
        context = {"entity": self.name}
        return ckan_request(
            "member_list",
            id=eid,
            object_type=member_kind,
            capacity=capacity,
            context=context,
        )


class PackageEntity(EntityWithExtras):
    """CKAN Entities based on packages.

    These entities all have a package_type.
    They currently include:
    - datasets
    - processes
    - workflows
    - tools

    Apart from standard operations, they also
    provide for search.
    """

    def __init__(self, *args, package_type: str, **kwargs):
        super().__init__(*args, extras_table="package", ckan_name="package", **kwargs)
        self.package_type = package_type
        self.ckan_api_purge = "dataset_purge"
        self.list_names = True
        self.operations.append("search")
        self.search_query_schema = schema.EntitySearchQuery()

    def list(self, limit=None, offset=None):
        """Return a list of package-based entities.

        This method is used to list the package-based entities of a given type.
        """
        self.check_limit_offset(limit, "limit")
        self.check_limit_offset(offset, "offset")

        # Return names or IDs?
        list_attr = "name" if self.list_names else "id"
        sql_query = sql.SQL(
            """\
            SELECT {list_attr} 
            FROM package 
            WHERE state = 'active' AND type = %s
            ORDER BY name
            LIMIT %s OFFSET %s"""
        ).format(list_attr=sql.Identifier(list_attr))
        # Package-derived entities are filtered by type using SQL, since
        # the package_list API call does not support filtering by type.
        result = execSql(sql_query, [self.package_type, limit, offset])
        return [row[list_attr] for row in result]

    def filter_ids(self, idlist: list[str]) -> list[dict]:
        """Filter the list of packages by ID, leaving only packages of one type."""
        return filter_list_by_type(idlist, self.package_type)

    def filter_names(self, idlist: list[str]) -> list[dict]:
        """Filter the list of packages by ID, leaving only packages of one type."""
        return filter_list_by_type(idlist, self.package_type, idattr="name")

    def create(self, init_data):
        # Make sure we have the two compulsory fields
        if "name" not in init_data:
            raise DataError("Missing name")
        if "owner_org" not in init_data:
            raise DataError("Missing owner_org")
        if "type" in init_data and init_data["type"] != self.package_type:
            raise DataError(f"Invalid type: {init_data['type']}")

        # Force this!
        init_data["type"] = self.package_type
        return super().create(init_data)

    def search(self, query_spec: dict) -> list:
        """Search for packages.

        This method is used to search for packages based on a query string.

        Args:
            q: The query string to search for.
            limit: The maximum number of packages to return.
            offset: The offset to start listing packages from.
        Returns:
            A list of package objects.

        q: str = None,
        bbox: list[float] = None,
        fq: list[str] = [],
        fl: list[str] = None,
        facet: dict = None,
        sort: str = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,

        """
        fl = query_spec.get("fl", None)
        limit = query_spec.get("limit", None)
        offset = query_spec.get("offset", None)

        self.check_limit_offset(limit, "limit")
        self.check_limit_offset(offset, "offset")

        bbox = query_spec.get("bbox", None)
        if bbox is not None:
            if len(bbox) != 4:
                raise DataError("bbox must have 4 numeric elements")

        result = entity_search(
            self.package_type,
            q=query_spec.get("q", None),
            bbox=bbox,
            fq=query_spec.get("fq", []),
            fl=fl,
            facet=query_spec.get("facet", None),
            sort=query_spec.get("sort", None),
            limit=limit,
            offset=offset,
        )

        # If fl is None, return proper entity objects
        if fl is None:
            new_results = [self.load_from_ckan(obj) for obj in result["results"]]
            result["results"] = new_results

        return result


class TagList(fields.Field):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return None
        return self.save_tags_to_ckan(value)

    def _deserialize(self, value, attr, data, **kwargs):
        if value is None:
            return None
        return self.load_tags_from_ckan(value)

    @staticmethod
    def save_tags_to_ckan(tags: list[str]) -> list[dict]:
        tagobjlist = []
        for tag in tags:
            try:
                tagobj = tag_string_to_object(tag)
            except ValueError as e:
                detail = {
                    "tagspec": tag,
                    "value_error": " ".join(str(arg) for arg in e.args),
                }
                raise DataError(*e.args, detail=detail)
            tagobjlist.append(tagobj)
        return tagobjlist

    @staticmethod
    def load_tags_from_ckan(tags: list[dict]) -> list[str]:
        return [tag_object_to_string(tagobj) for tagobj in tags]


class PackageSchema(Schema):
    """The front-end (API) schema for package-based entities"""

    id = fields.UUID(dump_only=True)
    metadata_created = fields.DateTime(dump_only=True)
    metadata_modified = fields.DateTime(dump_only=True)
    creator_user_id = fields.String(dump_only=True)

    state = fields.String(validate=validators.OneOf(["active", "deleted"]))
    type = fields.String(validate=validators.Equal("dataset"))
    name = schema.NameID()
    owner_org = fields.String(required=True)
    # By default, dataset metadata will be publicly available
    private = fields.Boolean(load_default=False)

    title = fields.String(allow_none=True)
    author = fields.String(allow_none=True)
    author_email = fields.String(allow_none=True)
    maintainer = fields.String(allow_none=True)
    maintainer_email = fields.String(allow_none=True)
    notes = fields.String(validate=validators.Length(0, 10000), allow_none=True)
    # Note: making this a URL would force checks that might fail
    url = fields.String(validate=validators.Length(0, 200), allow_none=True)
    version = fields.String(validate=validators.Length(0, 100), allow_none=True)

    resources = fields.List(fields.Dict(), dump_only=True)
    groups = fields.List(fields.Dict(), dump_only=True)
    tags = fields.List(fields.String)
    extras = fields.Dict(keys=fields.String())


class PackageCKANSchema(EntityWithExtrasCKANSchema):
    """The back-end (CKAN) schema for package-based entities.

    This schema is used to filter and transform the data to and from CKAN.
    Validation is not performed here.
    """

    # Read-only system attributes
    id = fields.String()
    metadata_created = fields.DateTime(load_only=True)
    metadata_modified = fields.DateTime(load_only=True)
    creator_user_id = fields.String(load_only=True)

    # System attributes that may be set
    state = fields.String()  # needed in UPDATE
    type = fields.String()  # needed in CREATE
    name = fields.String()  # needed in CREATE, UPDATE
    owner_org = fields.String()  # needed in CREATE, UPDATE
    private = fields.Boolean()

    # Dataset annotations
    title = fields.String(allow_none=True)
    author = fields.String(allow_none=True)
    author_email = fields.String(allow_none=True)
    maintainer = fields.String(allow_none=True)
    maintainer_email = fields.String(allow_none=True)
    notes = fields.String(allow_none=True)
    url = fields.String(allow_none=True)
    version = fields.String(allow_none=True)

    # ---- Licence stuff...
    # isopen = None
    # license_id = None
    # license_title = None
    # license_url = None

    # ---- TMI...
    # num_resources = None
    # num_tags = None
    # organization = None

    # ---- These seem defunct... user package_relationships_list
    # relationships_as_object = fields.Raw()
    # relationships_as_subject = fields.Raw()

    # ---- External stuff, need to be processed
    resources = fields.Raw()
    groups = fields.Raw()
    # ---- Extras are processed in the superclass
    # extras = fields.Raw()
    tags = TagList()

    class Meta:
        # Exclude all else from CKAN
        unknown = EXCLUDE
