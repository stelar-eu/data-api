"""Contains the Entity class and its subclasses. 

The Entity class is a base class for CKAN entities. It provides methods to interact with CKAN
and to perform CRUD operations on the entities. The subclasses of Entity are used to customize
specific CKAN entities, such as datasets, groups, and organizations. The subclasses define the
specific attributes and methods for each entity sub-type.

In particular, the EntityWithMembers class is used to handle CKAN entities that have members,
that is, groups and organizations. It provides methods to add, remove, and list members of the
group or organization. The MemberEntity class is used to customize the membership API in entities with
members.

"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Optional

from apiflask import Schema, fields, validators

import schema
from backend.ckan import ckan_request
from exceptions import DataError, ValidationError
from tags import tag_object_to_string, tag_string_to_object

if TYPE_CHECKING:
    from requests import Response

logger = logging.getLogger(__name__)


class Entity:
    """Base class for all API entities.

    In ReST terminology, an entity is a resource that can be accessed via an API.

    This class provides the basic structure for all entities. It defines the common
    operations that can be performed on an entity, such as listing, fetching, creating,
    updating, and deleting. The specific implementation of these operations is left to
    the subclasses.

    The API defined in this class is the one used by the generic endpoint definitions.
    """

    OPERATIONS = [
        "list",
        "fetch",
        "show",
        "create",
        "delete",
        "update",
        "patch",
    ]

    def __init__(self, name, collection_name, creation_schema, update_schema):
        self.name = name
        self.collection_name = collection_name

        self.creation_schema = creation_schema
        self.update_schema = update_schema

        # Store the endpoint functions
        self.operations = Entity.OPERATIONS.copy()
        if update_schema is None:
            self.operations.remove("update")
            self.operations.remove("patch")

        self.endpoints = {}
        logger.info("Instantiated entity %s", self.name)

    def list_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        raise NotImplementedError

    def fetch_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        raise NotImplementedError

    def get_entity(self, eid: str):
        raise NotImplementedError

    def create_entity(self, init_data):
        raise NotImplementedError

    def delete_entity(self, eid: str, purge=False):
        raise NotImplementedError

    def update_entity(self, eid: str, entity_data):
        raise NotImplementedError

    def patch_entity(self, eid: str, patch_data):
        raise NotImplementedError


class CKANEntity(Entity):
    def __init__(self, *args, ckan_name=None, extras=True, **kwargs):
        super().__init__(*args, **kwargs)

        self.ckan_name = ckan_name if ckan_name is not None else self.name
        self.ckan_api_list = f"{self.ckan_name}_list"
        self.ckan_api_show = f"{self.ckan_name}_show"
        self.ckan_api_create = f"{self.ckan_name}_create"
        self.ckan_api_delete = f"{self.ckan_name}_delete"
        self.ckan_api_purge = f"{self.ckan_name}_purge"
        self.ckan_api_update = f"{self.ckan_name}_update"
        self.ckan_api_patch = f"{self.ckan_name}_patch"

        self.has_extras = bool(extras)
        # Only packages have tags!
        self.has_tags = self.ckan_name in ("package", "vocabulary")

    def save_tags_to_ckan(self, tags: list[str]) -> list[dict]:
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

    def load_tags_from_ckan(self, tags: list[dict]) -> list[str]:
        return [tag_object_to_string(tagobj) for tagobj in tags]

    def save_extras_to_ckan(self, extras: dict) -> list[dict]:
        """Restructure a dict into the CKAN format"""
        extras_list = []
        for k, v in extras.items():
            sv = json.dumps(v)
            extras_list.append({"key": k, "value": sv})
        return extras_list

    def load_extras_from_ckan(self, extras: list[dict]) -> dict:
        """Restructure the CKAN extras into a dict"""
        edict = dict()
        for e in extras:
            try:
                val = json.loads(e["value"])
            except json.JSONDecodeError:
                val = e["value"]
            edict[e["key"]] = val
        return edict

    def save_to_ckan(self, init_data):
        # Implement the logic to save data to CKAN.
        # For performance, we perform conversion in place.
        if self.has_tags and "tags" in init_data:
            tags = init_data["tags"]
            init_data["tags"] = self.save_tags_to_ckan(tags)

        if self.has_extras and "extras" in init_data:
            init_data["extras"] = self.save_extras_to_ckan(init_data["extras"])

        return init_data

    def load_from_ckan(self, ci):
        if self.has_tags and "tags" in ci:
            ci["tags"] = self.load_tags_from_ckan(ci["tags"])

        if self.has_extras and "extras" in ci:
            ci["extras"] = self.load_extras_from_ckan(ci["extras"])

        return ci

    @staticmethod
    def check_limit_offset(val, name):
        if not isinstance(val, Optional[int]):
            raise DataError(f"{name} must be an integer, or None")
        if val is not None:
            if val < 0:
                raise ValidationError(f"{name} must be nonnegative")

    def list_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        self.check_limit_offset(limit, "limit")
        self.check_limit_offset(offset, "offset")
        return ckan_request(self.ckan_api_list, limit=limit, offset=offset)

    def fetch_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        entids = self.list_entities(limit=limit, offset=offset)
        ents = []
        for eid in entids:
            e = self.get_entity(eid)
            ents.append(e)
        return ents

    def get_entity(self, eid: str):
        obj = ckan_request(self.ckan_api_show, id=eid, context={"entity": self.name})
        return self.load_from_ckan(obj)

    def create_entity(self, init_data):
        context = {"entity": self.name}

        ckinit_data = self.save_to_ckan(init_data)

        obj = ckan_request(self.ckan_api_create, context=context, json=ckinit_data)
        logger.info("Created %s id=%s", self.name, obj["id"])
        return self.load_from_ckan(obj)

    def delete_entity(self, eid: str, purge=False):
        ckan_cmd = self.ckan_api_purge if purge else self.ckan_api_delete
        context = {"entity": self.name}
        result = ckan_request(ckan_cmd, id=eid, context=context)
        logger.info("%s %s id=%s", "Purged" if purge else "Deleted", self.name, eid)
        return result

    def update_entity(self, eid: str, entity_data):
        context = {"entity": self.name}

        ck_data = self.save_to_ckan(entity_data)

        obj = ckan_request(self.ckan_api_update, id=eid, context=context, json=ck_data)
        return self.load_from_ckan(obj)

    def patch_entity(self, eid: str, patch_data):
        context = {"entity": self.name}

        ckpatch_data = self.save_to_ckan(patch_data)

        obj = ckan_request(
            self.ckan_api_patch, id=eid, context=context, json=ckpatch_data
        )
        return self.load_from_ckan(obj)


def create_capacity_schema(
    name, capacities: re.Pattern | list[str] | None
) -> schema.Schema:
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


AnyCapacity = create_capacity_schema("AnyCapacity", None)
UserGroupCapacity = create_capacity_schema("UserGroupCapacity", ["editor", "member"])
UserOrgCapacity = create_capacity_schema(
    "UserOrgCapacity", ["admin", "editor", "member"]
)


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
        return self.parent.list_members(
            eid, self.member_kind, capacity=capacity, context=context
        )


class EntityWithMembers(CKANEntity):
    """This class treats CKAN entities which have members.

    This includes groups and organizations as well as any custom types derived
    from them (organizations are already a type of group).
    """

    def __init__(self, *args, members: list[MemberEntity] = [], **kwargs):
        super().__init__(*args, **kwargs)
        self.members = members
        for m in self.members:
            m.parent = self

    #
    # Because of a bug in CKAN code, getting CKAN groups and orgs fails (CKAN returns 'internal error')
    # when there are cycles between groups. To ameliorate this, we need to pass the 'include_groups=False'
    # flag.
    #
    # FYI: the bug is in file './ckan/lib/dictization/model_dictize.py' and manifests as a "stack overflow"
    # (in python the exception is "Recursion Depth exceeded").
    #
    def get_entity(self, eid: str):
        obj = ckan_request(
            self.ckan_api_show,
            id=eid,
            include_groups=False,
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
        obj = ckan_request(
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
