from __future__ import annotations

import functools
import json
import logging
import re
import traceback
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin

import requests
from apiflask import Schema, fields, validators
from flask import current_app

import schema
import utils
from exceptions import (
    BackendError,
    BackendLogicError,
    DataError,
    NotFoundError,
    ValidationError,
)
from routes.users import api_user_editor

if TYPE_CHECKING:
    from requests import Response

logger = logging.getLogger(__name__)


def raw_request(
    endpoint, *, json: Optional[dict] = None, headers: dict = {}, params=None, **kwargs
):
    """
    Sends a request to the CKAN API

    Args:
        endpoint (str): The API endpoint (relative to `api_url`). Can include query parameters.
        params (dict, optional): URL query parameters.
        headers (dict, optional): Additional request headers.
        json (dict, optional): JSON data to be sent in the body.

        **kwargs: These are added to json

    Returns:
        requests.Response: The response object from the API.
    """
    # Fetch the app config to gain access to URLs.
    config = current_app.config["settings"]

    # The base url of the CKAN API endpoint
    # Should be sth like http://ckan:5000/api/3/action/
    api_url = config["CKAN_API"]

    # Combine base_url with the endpoint
    url = urljoin(api_url, endpoint)

    # Prepare headers, defaulting to Authorization if token is present and Content-Type
    headers = {"Authorization": config["CKAN_ADMIN_TOKEN"]} | headers

    # Make the request using the provided method, url, params, data, json, and headers
    if kwargs:
        if json is None:
            request_args = kwargs
        else:
            request_args = json | kwargs
    else:
        request_args = json

    logger.debug("CKAN API call: %s %s", url, request_args)
    try:
        response = requests.post(
            url=url,
            json=request_args,
            headers=headers,
            params=params,
        )
    except Exception as e:
        message = "Request to CKAN failed: " + repr(e)
        detail = {
            "url": url,
            "request_args": str(request_args),
            "format_exc": traceback.format_exc(),
        }
        raise BackendError(500, "ckan", *e.args, message=message, detail=detail) from e

    logger.debug("CKAN API response: %d", response.status_code)
    return response


def request(
    endpoint, *, json: Optional[dict] = None, headers: dict = {}, params=None, **kwargs
):
    """Make a CKAN request and raise on error."""
    # Raise an exception for HTTP errors (4xx, 5xx responses)
    response = raw_request(
        endpoint, json=json, headers=headers, params=params, **kwargs
    )
    response.raise_for_status()
    return response


def raise_ckan_error(response: Response, context: dict):
    if 200 <= response.status_code < 300:
        return
    if 300 <= response.status_code < 400:
        raise BackendLogicError("ckan", "Unexpected redirect", response.status_code)
    if 400 <= response.status_code:
        c = response.json()
        etype = c["error"]["__type"]
        emsg = c["error"]["message"]
        context_detail = {
            k: v for k, v in context.items() if isinstance(v, (int, str, float, bool))
        }

        match etype:
            case "Integrity Error":
                raise DataError(emsg, detail=context_detail)
            case "Authorization Error":
                raise BackendLogicError("ckan", etype, emsg, detail=context_detail)
            case "Not Found Error":
                entity = context.get("entity", None)
                raise NotFoundError(entity, emsg, detail=context_detail)
            case "Validation Error":
                raise ValidationError(emsg, detail=context_detail)
            case "Search Query Error":
                raise DataError(etype, emsg, detail=context_detail)
            case "Search Error":
                raise ValidationError(etype, emsg, detail=context_detail)
            case "Search Index Error" | "Solr Connection Error" | "Internal Server Error":
                raise BackendError("ckan", etype, emsg, detail=context_detail)
            case _:
                raise BackendLogicError(
                    "ckan", "Unknown error type", etype, detail=context_detail
                )
    raise BackendLogicError(
        "ckan", "Unexpected status code", response.status_code, detail=context_detail
    )


def ckan_request(
    endpoint,
    *,
    json: Optional[dict] = None,
    headers: dict = {},
    params=None,
    context={},
    **kwargs,
):
    """Make a CKAN request and return the JSON response."""
    # Raise an exception for HTTP errors (4xx, 5xx responses)
    response = raw_request(
        endpoint, json=json, headers=headers, params=params, **kwargs
    )
    raise_ckan_error(response, context)
    jsobj = response.json()
    obj = jsobj["result"]
    return obj


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


def count_packages() -> int:
    """
    Returns the number of packages published in the CKAN data catalog
    by looking at the organization parameters.

    Returns:
        int: The count of packages or 0 if none are registered.

    Raises:
        RuntimeError: In case of error
    """
    try:
        response = request(
            "organization_show",
            json={
                "id": "stelar-klms",
                "include_dataset_count": True,
                "include_users": False,
            },
        )
        if response.status_code == 200:
            resp = response.json()
            org = resp.get("result", None)
            return org.get("package_count", 0)
        return 0
    except requests.exceptions.HTTPError as he:
        raise RuntimeError from he


def get_packages(
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    tag_filter: str = None,
    filter_mode: str = None,
):
    """
    Retrieve details for multiple datasets, with support for pagination.

    This function calls `list_packages` to get the list of dataset IDs,
    then fetches details for each dataset using `get_package`.

    Args:
        limit (int): The number of dataset IDs to retrieve (pagination).
        offset (int): The offset point to start retrieving datasets from.
        tag_filter (str):  Apply tag filter according to mode.
        filter_mode (str): Mode of the filter. 'keep' for keeping the matches,
        'discard' for discarding the matches

    Returns:
        dict: A dictionary where keys are dataset IDs, and values are the dataset details.

    Example:
        {
            "dataset_id_1": {...dataset details...},
            "dataset_id_2": {...dataset details...}
        }
    """
    # Retrieve a list of dataset IDs using the provided limit and offset
    packages = list_packages(limit=limit, offset=offset)

    # If no filtering is required, process all packages
    if not tag_filter or not filter_mode:
        return {package: get_package(package, compressed=True) for package in packages}

    # Process with filtering
    # VSAM: Note: this is currently used to filter datasets vs workflows etc, and will
    # be changed when/(if?) package types are supported in the catalog.
    result = {}
    for package in packages:
        pkg = get_package(package, compressed=True)
        # Check if the package matches the filtering criteria
        match_tag = tag_filter in pkg["tags"]
        if (filter_mode == "keep" and match_tag) or (
            filter_mode == "discard" and not match_tag
        ):
            result[package] = pkg

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
                dataset["organization"] = dataset["organization"]["title"]

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

                # Compress extras if compressed flag is True
                if compressed and "extras" in dataset:
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


def __get_vocabulary(name_or_id):
    """Return a vocabulary either by name or by id.

    The object returned
    """
    try:
        hresp = raw_request("vocabulary_show", json={"id": name_or_id})
        response = hresp.json()
        if response["success"]:
            vocab = response["result"]
            vocab["tagnames"] = {tag["name"] for tag in vocab["tags"]}
            return vocab
        else:
            raise ValueError("Vocabulary not found", name_or_id)
    except requests.exceptions.HTTPError as he:
        detail = {"errno": he.errno, "strerror": he.strerror, "url": he.request.url}
        raise BackendError(
            500, "CKAN failed on vocabulary access", name_or_id, detail=detail
        ) from he


@functools.lru_cache(maxsize=128)
def __get_cached_vocabulary(name_or_id):
    return {"vocab": __get_vocabulary(name_or_id), "fresh": True}


def get_vocabulary(name_or_id, cached=True):
    """Return a vocabulary either by name or by id.

    The object returned may be cached; if fetched by ID, its name
    and ID will be correct, since the ID is not repeatable and name
    is not volatile. However, tag information may be stale.

    If searched by name, the ID returned may be stale...
    Eventually, this will need to be fixed.
    """
    obj = __get_cached_vocabulary(name_or_id)
    if obj["fresh"]:
        obj["fresh"] = False
        return obj["vocab"]
    elif not cached:
        # Refresh
        voc = __get_vocabulary(name_or_id)
        obj["vocab"] = voc
        return voc
    else:
        return obj["vocab"]


def tag_object_to_string(tagobj):
    "Return a tag string for the given tag object"
    v = tagobj.get("vocabulary_id")  # ok if vocabulary_id is missing!
    if v is None:
        return tagobj["name"]
    else:
        voc = get_vocabulary(v)
        return ":".join((voc["name"], tagobj["name"]))


TAGSPEC_PATTERN = re.compile(r"((.{2,100})\:)?([a-z0-9_-]{2,100})")


def tag_split(tagspec: str) -> tuple[str | None, str]:
    """Split a tag string into a pair or (<vocabulary-name> , <tag-name>).

    Properly, a tagspec is either <tag-name>  or <vocabulary-name>:<tag-name>,
    where
        <tagname> is a string made only of lower-case alphanumerics, hyphen (-) and underscore (_),
        and of length in [2,100]
        <vocabulary-name> is any string (which may contain spaces and other ascii characters) of
        length [2,100].
    """
    m = TAGSPEC_PATTERN.fullmatch(tagspec)
    if m is None:
        raise ValueError(f"Invalid tagspec: {tagspec}")
    return m.groups()[1:]


def tag_string_to_object(tagspec):
    """Convert a tagspec (vocab:tagname) to an object, suitable for
    sending to CKAN.

    Args:
        tagspec (str): the tagspec to convert.
    Returns:
        an object for the tagspec.
    Raises:
        ValueError if the vocabulary cannot be found or the tag string is badly formed.
    """
    vocname, tagname = tag_split(tagspec)
    if vocname is None:
        return {"name": tagname}
    else:
        vocab = get_vocabulary(vocname)
        if tagname in vocab["tagnames"]:
            return {"name": tagname, "vocabulary_id": vocab["id"]}
        else:
            raise ValueError(f"Tag '{tagname}' not in vocabulary '{vocab['name']}'")


# ------------------------------------------------------------
#  Generic stuff
# ------------------------------------------------------------


class Entity:
    OPERATIONS = [
        "list",
        "fetch",
        "show",
        "create",
        "delete",
        "update",
        "patch",
    ]

    def __init__(
        self,
        name,
        collection_name,
        creation_schema,
        update_schema,
        ckan_name=None,
        extras=True,
    ):
        self.name = name
        self.collection_name = collection_name

        self.ckan_name = ckan_name if ckan_name is not None else name
        self.ckan_api_list = f"{self.ckan_name}_list"
        self.ckan_api_show = f"{self.ckan_name}_show"
        self.ckan_api_create = f"{self.ckan_name}_create"
        self.ckan_api_delete = f"{self.ckan_name}_delete"
        self.ckan_api_purge = f"{self.ckan_name}_purge"
        self.ckan_api_update = f"{self.ckan_name}_update"
        self.ckan_api_patch = f"{self.ckan_name}_patch"

        self.creation_schema = creation_schema
        self.update_schema = update_schema

        self.has_extras = bool(extras)
        # Only packages have tags!
        self.has_tags = self.ckan_name in ("package", "vocabulary")

        # Store the endpoint functions
        self.operations = Entity.OPERATIONS.copy()
        if update_schema is None:
            self.operations.remove("update")
            self.operations.remove("patch")

        self.endpoints = {}

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


class EntityWithMembers(Entity):
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


# ------------------------------------------------------------
#  STELAR Entities
# ------------------------------------------------------------

DATASET = Entity(
    "datset",
    "datsets",
    creation_schema=schema.DatasetSchema(),
    update_schema=schema.DatasetSchema(partial=True),
    ckan_name="package",
)
DATASET.ckan_api_purge = "dataset_purge"

RESOURCE = Entity(
    "resrc",
    "rsrcs",
    schema.ResourceCreationRequest,
    schema.ResourceUpdateRequest,
    ckan_name="resource",
    extras=False,
)


GROUP = EntityWithMembers(
    "group",
    "groups",
    schema.GroupSchema(),
    schema.GroupSchema(partial=True),
)

ORGANIZATION = EntityWithMembers(
    "organization",
    "organizations",
    schema.OrganizationSchema(),
    schema.OrganizationSchema(partial=True),
)

GROUP.members = [
    MemberEntity(GROUP, DATASET, AnyCapacity),
    MemberEntity(GROUP, GROUP, AnyCapacity),
    # users: editor, member
]

ORGANIZATION.members = [
    MemberEntity(ORGANIZATION, DATASET, AnyCapacity),
    MemberEntity(ORGANIZATION, GROUP, AnyCapacity),
    # users: editor, member, admin
]


class VocabularyEntity(Entity):
    def __init__(self):
        super().__init__(
            "vocabulary",
            "vocabularies",
            schema.VocabularyCreationRequest,
            schema.VocabularyUpdateRequest,
            extras=False,
        )
        self.operations.remove("patch")

    def list_entities(self, limit=None, offset=None):
        """Return the list of vocabulary names"""
        # CKAN returns a list of objects, breaking the API.
        entities = ckan_request(self.ckan_api_list, limit=limit, offset=offset)
        return [e["name"] for e in entities]

    def fetch_entities(self, limit=None, offset=None):
        entities = ckan_request(self.ckan_api_list, limit=limit, offset=offset)
        return [self.load_from_ckan(e) for e in entities]


VOCABULARY = VocabularyEntity()

TAG = Entity("tag", "tags", schema.TagCreationRequest, None, extras=False)

# MEMBER = Entity("member", "members", schema.MemberCreationRequest, None)
