from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional

import requests
from apiflask import Schema, fields, validators
from marshmallow import EXCLUDE, INCLUDE, post_dump

import schema
import utils
from backend.ckan import ckan_request, request
from backend.pgsql import execSql
from entity import (
    AnyCapacity,
    CKANEntity,
    EntityWithExtrasCKANSchema,
    EntityWithMembers,
    MemberEntity,
    PackageCKANSchema,
    PackageEntity,
    PackageSchema,
)
from exceptions import DataError
from routes.users import api_user_editor
from search import resource_search
from spatial import GeoJSONGeom, Spatial
from tools import TOOL
from wflow import WORKFLOW

logger = logging.getLogger(__name__)


def is_package(id: str):
    """Checks if a given ID corresponds a valid existing dataset in CKAN.

    Args:
      id: The ID under examination.

    Returns:
        bool: true/false depending to the validity of the ID as package.
    """
    try:
        if id:
            response = request("package_show", json={"id": id})
            if response.status_code == 200:
                return True
        else:
            return False
    except Exception:
        return False


def is_resource(id: str):
    """Checks if a given ID corresponds a valid existing resource in CKAN.

    Args:
      id: The ID under examination.

    Returns:
        bool: true/false depending to the validity of the ID as resource.
    """
    try:
        if id:
            response = request("resource_show", params={"id": id})
            if response.status_code == 200:
                return True
        else:
            return False
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            return False
    except Exception:
        return False


def search_packages(
    keyword: str, limit: int = 0, offset: int = 0, expand_mode: bool = False
):
    """
    Search for datasets in the CKAN catalog using a keyword.

    This function interacts with the CKAN API to search datasets in the catalog using
    the `package_search` endpoint. It allows filtering datasets by a keyword and can
    return either basic or detailed package information.

    Args:
        keyword (str): The search keyword to filter datasets.
        limit (int): The number of results to return. If 0, no limit is applied.
        offset (int): The starting point (offset) to fetch the search results from.
        expand_mode (bool): If True, fetch detailed metadata for each dataset.

    Returns:
        list: A list of dictionaries containing package details.

    Raises:
        Exception: If an error occurs while performing the search.

    Example:
        Response: [
            {"id": "dataset_id_1", "name": "Dataset 1", ...},
            {"id": "dataset_id_2", "name": "Dataset 2", ...}
        ]
    """
    try:
        # Validate limit and offset
        if limit < 0 or offset < 0:
            raise ValueError("Limit and offset must be non-negative integers.")

        # Prepare query parameters
        params = {
            "q": keyword,
            "start": offset,
            "rows": (
                limit if limit > 0 else 1000
            ),  # Default to a high limit if no limit is specified
        }

        # Make the request to the CKAN API
        response = request("package_search", json=params)

        if response.status_code == 200:
            results = response.json()["result"]["results"]

            if expand_mode:
                # Fetch detailed metadata for sorting or further processing
                detailed_results = []
                for dataset in results:
                    dataset_info = get_package(
                        dataset["id"], include_extras=True, include_resources=True
                    )
                    detailed_results.append(dataset_info)

                return detailed_results
            else:
                # Return basic search results
                return results
        else:
            # Handle error responses from the API
            raise Exception(
                f"CKAN API returned an error: {response.status_code} - {response.text}"
            )

    except Exception as e:
        # Raise the exception if an error occurs during processing
        raise Exception(f"Error while searching packages: {str(e)}")


def list_packages(
    limit: Optional[int] = None, offset: Optional[int] = None, expand_mode: bool = False
):
    """
    Retrieve a list of all dataset IDs from the CKAN catalog.

    This function interacts with the CKAN API to fetch the list of all available
    datasets in the catalog. It calls the `package_list` endpoint, which returns
    only the unique identifiers (IDs) of the datasets.

    Args:
        limit (int): The number of dataset IDs to return. If None, no limit is applied.
        offset (int): The starting point (offset) to fetch the dataset IDs from.

    Returns:
        list: A list of dataset IDs if the request is successful.

    Raises:
        Exception: If an error occurs while fetching the dataset list.

    Example:
        Response: ["dataset_id_1", "dataset_id_2", "dataset_id_3"]
    """

    def check(val, name):
        if not isinstance(val, Optional[int]):
            raise TypeError(f"{name} must be an integer, or None")
        if val is not None:
            if val < 0:
                raise ValueError(f"{name} must be nonnegative")

    check(limit, "limit")
    check(offset, "offset")

    try:
        # Make the request to the CKAN API using the constructed parameters
        response = request("package_list", limit=limit, offset=offset)
        if response.status_code == 200:
            datasets = response.json()["result"]
            if expand_mode:
                # Fetch detailed metadata for sorting
                detailed_datasets = []
                for dataset in datasets:
                    dataset_info = get_package(dataset, True, True)
                    detailed_datasets.append(dataset_info)

                sorted_datasets = sorted(
                    detailed_datasets,
                    key=lambda x: datetime.fromisoformat(x["metadata_modified"]),
                    reverse=True,
                )

                paginated_datasets = (
                    sorted_datasets[offset : offset + limit]  # noqa
                    if limit > 0
                    else sorted_datasets
                )
                return paginated_datasets

            else:
                return datasets
        else:
            return None

    except Exception:
        # If an error occurs during the request, raise a general exception
        raise


def count_packages(type: str = None) -> int:
    """
    Returns the number of packages published in the CKAN data catalog
    by looking at the organization parameters.

    Returns:
        int: The count of packages or 0 if none are registered.

    Raises:
        RuntimeError: In case of error
    """
    if type is not None:
        query = "SELECT COUNT(*) FROM package WHERE state='active' AND type=%s"
        result = execSql(query, (type,))
    else:
        query = "SELECT COUNT(*) FROM package WHERE state='active'"
        result = execSql(query, ())
    return result[0]["count"]


def fetch_packages(
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    type_filter: str = None,
):
    """
    Retrieve details for multiple packages, with support for pagination.

    Args:
        limit (int): The number of dataset IDs to retrieve (pagination).
        offset (int): The offset point to start retrieving datasets from.
        tag_filter (str):  Apply tag filter according to mode.
        filter_mode (str): Mode of the filter. 'keep' for keeping the matches,
        'discard' for discarding the matches

    Returns:
        dict: A dictionary where keys are package IDs, and values are package details.

    Example:
        {
            "dataset_id_1": {...dataset details...},
            "dataset_id_2": {...dataset details...}
        }
    """

    query = """SELECT id, title, name, author, notes, type FROM package 
                WHERE state='active' AND type != 'tool' 
                ORDER BY metadata_modified DESC"""
    if limit:
        query += f" LIMIT {limit}"
    if offset:
        query += f" OFFSET {offset}"
    result = execSql(query)

    for row in result:
        logger.debug(row)

    return result


def get_package(
    id: str, compressed: bool = False, no_resources: bool = False, title: str = None
):
    """Retrieve a dataset's details from the CKAN catalog using its unique identifier.

    This function interacts with the CKAN API to fetch metadata about a specific dataset.
    It is designed to work without requiring authentication, leveraging CKAN's support for
    unauthenticated GET requests.

    Args:
        id (str): The unique identifier (name) of the dataset to retrieve.
        compressed (bool): Whether to compress the dataset's 'resources' field.
        no_resources (bool): Whether to exclude the 'resources' field from the dataset.
        title (str): The title of the dataset to retrieve. If provided, it will be converted
        to an ID and dominate any ID provided.

    Returns:
        dict or None: The dataset's details as a dictionary if found, otherwise None.

    Raises:
        ValueError: If the dataset with the specified ID is not found (HTTP 404).
        RuntimeError: For any other HTTP errors encountered while making the request.
    """
    try:
        # If title is provided, convert it to a valid ID
        if title:
            id = re.sub(r"[\W_]+", "_", title).lower()

        response = request("package_show", params={"id": id})
        if response.status_code == 200:
            resp = response.json()
            dataset = resp.get("result", None)

            if dataset:

                if no_resources and "resources" in dataset:
                    dataset.pop("resources")

                # Compress resources if compressed flag is True
                if compressed and "resources" in dataset:
                    dataset["resources"] = [
                        {
                            "id": resource.get("id"),
                            "name": resource.get("name"),
                            "url": resource.get("url"),
                            "relation": resource.get("relation"),  # Include if present
                        }
                        for resource in dataset["resources"]
                    ]

                # Compress tags if compressed flag is True
                if compressed and "tags" in dataset:
                    dataset["tags"] = [tag.get("name") for tag in dataset["tags"]]

                # Compress extras
                if "extras" in dataset:
                    dataset["extras"] = {
                        extra.get("key"): extra.get("value")
                        for extra in dataset["extras"]
                    }

            return dataset
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Dataset with ID: {id} was not found")
        else:
            raise RuntimeError from he


def create_package(
    basic_metadata: dict, extra_metadata: dict = None, profile_metadata: dict = None
):
    """This method utilizes the CKAN API to publish a package in the catalog.
    The package published can be defined w/ or w/out resources, w/ or w/out extra metadata
    and w/ or w/out profile metadata. Inside the basic_metadata resources can be defined or not.
    The package that is to be published can have three fields.

    Args:
    - basic_metadata: (dict) A dict containing the basic information about the package
      (name(unique), description, tags etc.)
    - extra_metadata: (dict, optional) Any special metadata such as theme, spatial etc.
    - profile_metadata: (dict, optional) Any information about an already generated profile
      that is linked to the package as resource

    """

    # --------- Handle the required basic_metadata of the package
    if basic_metadata:
        basic_metadata["name"] = re.sub(r"[\W_]+", "_", basic_metadata["title"]).lower()
        basic_metadata["tags"] = utils.handle_keywords(basic_metadata["tags"])

        resp_org = api_user_editor()
        if resp_org["success"]:
            org_json = resp_org["result"]
            if len(org_json) > 0:
                for item in org_json:
                    if (
                        item["type"] == "organization"
                        and item["state"] == "active"
                        and item["capacity"] in ("admin", "editor")
                    ):
                        basic_metadata["owner_org"] = org_json[0][
                            "name"
                        ]  # CAUTION! Taking the first organization where this user is editor
                        break
        try:
            resp_basic = request("package_create", json=basic_metadata)
            if resp_basic.status_code == 200:
                package_id = resp_basic.json()["result"]["id"]
        except requests.exceptions.HTTPError as he:
            if he.response.status_code == 409:
                raise AttributeError("Package title already exists.")
            else:
                raise RuntimeError from he

    else:
        raise ValueError(
            "No basic metadata provided for publishing in the Catalog. Please specify some basic metadata"
            " (title, description, tags, etc.) for the dataset you wish to publish."
        )

    # --- Handle the optional extra_metadata of the package
    if extra_metadata:
        extras = {}
        extras["id"] = package_id
        extras["extras"] = utils.handle_extras(extra_metadata)

        resp_extras = request("package_patch", json=extras)
        if resp_extras.status_code != 200:
            raise RuntimeError(resp_extras.json()["result"])

    # --- Handle the optional profile_metadata of the package
    if profile_metadata is not None:
        profile_metadata["package_id"] = package_id
        if profile_metadata.get("file") is not None:
            pass
            # with open(profile_metadata['file'], 'rb') as f:
            #     resp_resource = request("POST","resource",'resource_create',
            #                   json=resource_metadata, headers=resource_headers, files=[('upload', f)])
            #     arr_resp.append(resp_resource.json())
            #     resource_id = resp_resource.json()['result']['id']
            #     f1 = open(resource_metadata['file'])
            #     profile = json.load(f1)
            #     sql_commands = utils.extractProfileProperties(resource_id, profile)
            #     for sql in sql_commands:
            #         utils.execSql(sql)
        elif profile_metadata.get("url") is not None:
            profile_metadata["relation"] = "profile"
            resp_resource = request("resource_create", json=profile_metadata)
            if resp_resource.status_code != 200:
                raise RuntimeError(resp_extras.json()["result"])
        else:
            raise ValueError(
                "No profile metadata were associated with this dataset in the Catalog. Please provide "
                "a path or a publicly accessible URL where this file is available."
            )

    # --- Return the newly created package by fetching it from the catalog
    new_package_resp = request("package_show", params={"id": package_id})

    if new_package_resp.status_code == 200:
        return new_package_resp.json()["result"]
    else:
        raise RuntimeError(new_package_resp.json["result"])


def patch_package(id: str, package_metadata: dict):
    """
    This method utilizes the CKAN API to PATCH a package in the catalog.
    The package to be PATCHED must be defined with package metadata.
    Inside the package_metadata, resources cannot be defined or they will be omitted.

    Args:
    - id (str): The unique identifier for the dataset package that needs to be patched.
    - package_metadata (dict): A dictionary containing metadata to update the package (e.g.,
      name, description, tags, etc.)

    Returns:
    - dict: The updated package information if successful.

    Raises:
    - ValueError: If the dataset with the given ID is not found.
    - Exception: For other types of exceptions during the request.
    """
    try:
        package_metadata["id"] = id
        if package_metadata.get("resources"):
            package_metadata.pop("resources")

        # Handle keywords appropriately
        if package_metadata.get("tags"):
            package_metadata["tags"] = utils.handle_keywords(package_metadata["tags"])

        response = request("package_patch", json=package_metadata)
        if response.status_code == 200:
            return response.json().get("result")

    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Dataset with ID: {id} was not found")
        else:
            raise Exception from he
    except Exception as e:
        raise Exception from e


def delete_package(id: str):
    try:
        if id:
            response = request("dataset_purge", json={"id": id})
            if response.status_code == 200:
                return id
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Package with ID: {id} was not found")
        elif he.response.status_code == 409:
            raise AttributeError("Conflict error")
    except Exception as e:
        raise Exception from e


def get_package_resources(package_id: str, relation_filter: str = None):
    try:
        package = get_package(package_id)

        if relation_filter and isinstance(relation_filter, str):
            package["resources"] = [
                resource
                for resource in package["resources"]
                if resource.get("relation", "") == relation_filter
            ]

        return package["resources"]

    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Package with ID: {package_id} was not found")
    except Exception as e:
        raise Exception from e


def get_resource(id: str):
    try:
        if id:
            response = request("resource_show", json={"id": id})
            if response.status_code == 200:
                return response.json()["result"]
        else:
            raise ValueError("ID cannot be empty")
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Resource with ID: {id} was not found")
    except Exception as e:
        raise Exception from e


def create_resource(
    package_id: str, resource_metadata: dict, relation_type: str = "owned"
) -> dict:
    try:
        if package_id:
            resource_metadata["package_id"] = package_id
            resource_metadata["relation"] = relation_type

            response = request("resource_create", json=resource_metadata)

            if response.status_code == 200:
                resource_id = response.json()["result"]["id"]
                if resource_metadata.get("resource_type"):
                    sql_commands = utils.extractResourceProperties(
                        resource_id, resource_metadata
                    )
                    for sql in sql_commands:
                        utils.execSql(sql)

            return response.json()["result"]

    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Package with ID: {package_id} was not found")
    except Exception as e:
        raise Exception from e


def patch_resource(id: str, resource_metadata: dict):
    try:
        if id:
            resource_metadata["id"] = id
            response = request("resource_patch", json=resource_metadata)
            if response.status_code == 200:
                return response.json()["result"]
        else:
            raise ValueError("ID cannot be empty")
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Resource with ID: {id} was not found")
        if he.response.status_code == 400:
            raise AttributeError(f"Missing parameters: {he}")
    except Exception as e:
        raise Exception from e


def delete_resource(id: str):
    try:
        if id:
            # Performing double delete because CKAN needs 2 resource delete requests
            # to hard delete a resource.
            # Ugh....
            response = request("resource_delete", json={"id": id})
            # VSAM: Actually, take this back! eventually we are going to honor the CKAN soft delete,
            # so we will not delete the resource twice.
            # if response.status_code == 200:
            #    response = request("resource_delete", json={"id": id})
            if response.status_code == 200:
                return id
        else:
            raise ValueError("ID cannot be empty")
    except requests.exceptions.HTTPError as he:
        raise ValueError(f"Resource with ID: {id} was not found", he)


# ------------------------------------------------------------
#  Generic stuff
#  STELAR Catalog Entities
# ------------------------------------------------------------


# ------------------------------------------------------------
# Dataset and Resources
# ------------------------------------------------------------


class DatasetSchema(PackageSchema):
    spatial = GeoJSONGeom(required=False, allow_none=True, dump_default=None)


class DatasetCKANSchema(PackageCKANSchema):
    spatial = Spatial(required=False, allow_none=True, load_default=None)

    class Meta(PackageCKANSchema.Meta):
        extra_attributes = ["spatial"]
        extra_attributes_raw = ["spatial"]


DATASET = PackageEntity(
    "dataset",
    "datasets",
    creation_schema=DatasetSchema(),
    update_schema=DatasetSchema(partial=True),
    package_type="dataset",
    ckan_schema=DatasetCKANSchema(),
)


class ResourceSchema(Schema):
    id = fields.UUID(dump_only=True)
    created = fields.DateTime(dump_only=True)
    last_modified = fields.DateTime(allow_none=True)
    package_id = fields.UUID(required=True)

    url = fields.String(allow_none=True)
    format = fields.String(allow_none=True)
    name = fields.String(allow_none=True)
    description = fields.String(allow_none=True)
    resource_type = fields.String(
        validate=validators.OneOf(["file", "api", "service"]), allow_none=True
    )
    hash = fields.String(allow_none=True)
    size = fields.Integer(allow_none=True)
    mimetype = fields.String(allow_none=True)
    mimetype_inner = fields.String(allow_none=True)
    cache_url = fields.String(allow_none=True)
    cache_last_updated = fields.DateTime(allow_none=True)

    # extra = fields.Dict(required=False, allow_none=True)

    class Meta:
        unknown = INCLUDE


class ResourceCKANSchema(Schema):
    id = fields.String()
    created = fields.DateTime(load_only=True)
    last_modified = fields.DateTime(allow_none=True)

    package_id = fields.String()

    url = fields.String(allow_none=True)
    format = fields.String(allow_none=True)
    name = fields.String(allow_none=True)
    description = fields.String(allow_none=True)
    resource_type = fields.String(allow_none=True)
    hash = fields.String(allow_none=True)
    size = fields.Integer(allow_none=True)
    mimetype = fields.String(allow_none=True)
    mimetype_inner = fields.String(allow_none=True)
    cache_url = fields.String(allow_none=True)
    cache_last_updated = fields.DateTime(allow_none=True)

    class Meta:
        unknown = INCLUDE

    @post_dump(pass_original=True)
    def include_resource_extras(self, data, original, **kwargs):
        return original | data


class ResourceEntity(CKANEntity):
    def __init__(self):
        super().__init__(
            "resource",
            "resources",
            ResourceSchema(),
            ResourceSchema(partial=True),
            ckan_name="resource",
            ckan_schema=ResourceCKANSchema(),
        )
        self.operations.remove("list")
        self.operations.remove("fetch")
        self.operations.append("search")
        self.search_query_schema = schema.ResourceSearchQuery()

    def search(self, query_spec):
        """Search for resources in the catalog.

        Args:
            query_spec (dict): A dictionary containing the search query parameters.

        Returns:
            list: A list of resource objects that match the search criteria.
        """
        query = query_spec["query"]
        order_by = query_spec.get("order_by", None)
        limit = query_spec.get("limit", None)
        offset = query_spec.get("offset", None)

        # Perform the search
        result = resource_search(query, order_by=order_by, limit=limit, offset=offset)

        # Properly format the search results
        new_results = [self.load_from_ckan(r) for r in result["results"]]
        result["results"] = new_results
        return result


RESOURCE = ResourceEntity()

# ------------------------------------------------------------
# Groups and Organizations
# ------------------------------------------------------------


class GroupSchema(Schema):
    id = fields.UUID(dump_only=True)
    name = schema.NameID()
    created = fields.DateTime(dump_only=True)
    state = fields.String(
        required=False, validate=validators.OneOf(["draft", "active", "deleted"])
    )

    title = fields.String()
    description = fields.String()
    image_url = fields.String()
    type = fields.String(validate=validators.OneOf(["group", "organization"]))
    approval_status = fields.String(
        validate=validators.OneOf(["approved", "pending", "rejected"]),
    )

    is_organization = fields.Boolean(dump_only=True)

    # It seems that Groups and Organizations do not support tags, and furthermore,
    # the CKAN decision was to drop them altogether from groups and organizations
    #
    # https://github.com/ckan/ckan/issues/4388
    #
    # tags = List(String, required=False)

    extras = fields.Dict(required=False)


class OrganizationSchema(GroupSchema):
    pass


class EntityWithMembersCKANSchema(EntityWithExtrasCKANSchema):
    id = fields.String()
    name = schema.NameID()
    created = fields.DateTime(load_only=True)
    state = fields.String()

    title = fields.String(allow_none=True)
    description = fields.String(allow_none=True)
    image_url = fields.String(allow_none=True)
    type = fields.String()
    approval_status = fields.String()

    is_organization = fields.Boolean(load_only=True)

    # It seems that Groups and Organizations do not support tags, and furthermore,
    # the CKAN decision was to drop them altogether from groups and organizations
    #
    # https://github.com/ckan/ckan/issues/4388
    #
    # tags = List(String, required=False)

    class Meta:
        unknown = EXCLUDE


GROUP = EntityWithMembers(
    "group",
    "groups",
    GroupSchema(),
    GroupSchema(partial=True),
    ckan_name="group",
    ckan_schema=EntityWithMembersCKANSchema(),
)

ORGANIZATION = EntityWithMembers(
    "organization",
    "organizations",
    OrganizationSchema(),
    OrganizationSchema(partial=True),
    ckan_name="organization",
    ckan_schema=EntityWithMembersCKANSchema(),
)


#
# Users are not implemented as Entities yet, so to make them members we need to customize the MemberEntity
# class.
#

_USER = CKANEntity("user", "users", None, None, ckan_name="user", ckan_schema=None)


class UserMember(MemberEntity):
    """Specialize member entity for users.

    This is needed because the current implementation for users is not
    based on the Entity class.
    """

    def __init__(self, group, capacity):
        super().__init__(group, _USER, capacity)


GROUP.members = [
    MemberEntity(GROUP, DATASET, AnyCapacity),
    MemberEntity(GROUP, WORKFLOW, AnyCapacity),
    MemberEntity(GROUP, TOOL, AnyCapacity),
    MemberEntity(GROUP, GROUP, AnyCapacity),
    UserMember(GROUP, AnyCapacity),
]

ORGANIZATION.members = [
    MemberEntity(ORGANIZATION, DATASET, AnyCapacity),
    MemberEntity(ORGANIZATION, WORKFLOW, AnyCapacity),
    MemberEntity(ORGANIZATION, TOOL, AnyCapacity),
    MemberEntity(ORGANIZATION, GROUP, AnyCapacity),
    UserMember(ORGANIZATION, AnyCapacity),
]


# ------------------------------------------------------------
# Tags and Vocabulary
# ------------------------------------------------------------


class TagSchema(Schema):
    id = fields.UUID(dump_only=True)
    name = schema.TagName()
    vocabulary_id = fields.String(required=True, allow_none=True)


class TagCKANSchema(Schema):
    id = fields.String()
    name = schema.TagName()
    vocabulary_id = fields.String(allow_none=True)

    class Meta:
        unknown = EXCLUDE


class VocabularySchema(Schema):
    id = fields.UUID(dump_only=True)
    name = schema.NameID()
    # tags = fields.List(schema.TagName, required=True)
    tags = fields.List(fields.Raw, required=True)


class VocabularyCKANSchema(Schema):
    id = fields.String()
    name = schema.String()
    tags = fields.List(fields.Raw)

    # @post_dump
    def convert_tags(self, data, **kwargs):
        tags = data.get("tags", [])
        data["tags"] = [{"name": tag} for tag in tags]
        return data

    # @pre_load
    def unwrap_tags(self, data, **kwargs):
        tags = data.get("tags", [])
        data["tags"] = [tag["name"] for tag in tags]
        return data

    class Meta:
        unknown = EXCLUDE


class VocabularyEntity(CKANEntity):
    def __init__(self):
        super().__init__(
            "vocabulary",
            "vocabularies",
            VocabularySchema(),
            VocabularySchema(partial=True),
            ckan_name="vocabulary",
            ckan_schema=VocabularyCKANSchema(),
        )
        self.operations.remove("patch")

    def list_entities(self, limit=None, offset=None):
        """Return the list of vocabulary names"""
        # CKAN returns a list of objects, breaking the API.
        entities = ckan_request(self.ckan_api_list)
        return [e["name"] for e in entities]

    def fetch_entities(self, limit=None, offset=None):
        """Return the list of vocabulary objects.

        This method is actually calling the CKAN API to fetch the list
        of vocabulary objects.

        Args:
            limit (int): This argument is ignored.
            offset (int): This argument is ignored.
        """
        entities = ckan_request(self.ckan_api_list)
        return [self.load_from_ckan(e) for e in entities]

    def delete(self, eid: str, purge=False):
        """Delete a vocabulary.

        To delete a vocabulary in CKAN, it is necessary to first delete all tags
        associated with it. This method will do that.

        Args:
            eid (str): The ID or name of the vocabulary to delete.
            purge (bool): Actually, this is ignored. Vocabulary deletion is a purge.
        """
        # Fetch the vocabulary object
        vocab = self.get(eid)

        # Delete all tags associated with the vocabulary
        for tag in vocab["tags"]:
            TAG.delete(tag["id"])

        # Delete the vocabulary
        return super().delete(eid)


VOCABULARY = VocabularyEntity()


class TagEntity(CKANEntity):
    def __init__(self):
        super().__init__(
            "tag",
            "tags",
            TagSchema(),
            None,
            ckan_name="tag",
            ckan_schema=TagCKANSchema(),
        )

    def create(self, data: dict):
        """Create a new vocabulary tag object in CKAN."""
        name = data["name"]
        vocab = data["vocabulary_id"]
        if vocab is None:
            raise DataError("Vocabulary ID is required to create a tag.")
        obj = ckan_request(
            self.ckan_api_create,
            name=name,
            vocabulary_id=vocab,
            context={"entity": self.name},
        )
        return self.load_from_ckan(obj)

    def get(self, eid: str):
        """Return a tag object by name or id."""

        # Check if we have a tagspec
        if ":" in eid:
            vocab, tag = eid.rsplit(":", 1)
            obj = ckan_request(
                self.ckan_api_show,
                id=tag,
                vocabulary_id=vocab,
                context={"entity": self.name},
            )
            return self.load_from_ckan(obj)
        else:
            # Either we have a free tag name or a UUID, so..,
            return super().get(eid)

    def delete(self, eid: str, purge=False):
        if ":" in eid:
            vocab, tag = eid.split(":")
            return ckan_request(
                self.ckan_api_delete,
                id=tag,
                vocabulary_id=vocab,
                context={"entity": self.name},
            )
        else:
            return super().delete(eid)


TAG = TagEntity()
