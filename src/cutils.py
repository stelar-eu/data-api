from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional

import requests
from apiflask import Schema, fields, validators
from marshmallow import EXCLUDE, INCLUDE, post_dump
from processes import PROCESS
from typing import List, Dict
from datetime import datetime

import schema
import uuid
import kutils
import utils
from backend.ckan import ckan_request, request
from backend.pgsql import execSql
import sql_utils
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
from exceptions import DataError, InvalidError, InternalException, ConflictError
from authz import authorize
from routes.users import api_user_editor
from search import resource_search
from spatial import GeoJSONGeom, Spatial
from tools import TOOL
from tasks import TASK
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


def get_package(id: str):
    """Retrieve package details from the CKAN catalog using its unique identifier.
    The retrieval is based on the type of the package and returns the respective
    authorized get_entity method for the package type.

    Returns:
        dict or None: The package details as a dictionary if found, otherwise None
    """

    ptype = PackageEntity.resolve_type(id)

    if ptype == "tool":
        return TOOL.get_entity(id)
    elif ptype == "workflow":
        return WORKFLOW.get_entity(id)
    elif ptype == "dataset":
        return DATASET.get_entity(id)
    elif ptype == "process":
        return PROCESS.get_entity(id)


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

    def create_entity(self, init_data):
        """Create a new resource.

        This method is used to create a new resource. Authorization check
        is relying on whether the relevant permission add_resource is granted
        for the package the resource is destined to be added to.

        Args:
            init_data: The data to initialize the entity with.
        Returns:
            The created entity object.
        """
        init_data["package_id"] = str(init_data["package_id"])  # Normalize UUID
        init_data["package_type"] = PackageEntity.resolve_type(init_data["package_id"])
        authorize(init_data["package_id"], init_data["package_type"], "update")

        return self.create(init_data)

    def update_entity(self, eid, entity_data):
        entity_data["package_id"] = str(entity_data["package_id"])  # Normalize UUID
        entity_data["package_type"] = PackageEntity.resolve_type(
            entity_data["package_id"]
        )
        authorize(entity_data["package_id"], entity_data["package_type"], "update")

        return self.update(eid, entity_data)

    def patch_entity(self, eid, patch_data):
        spec = self.get_cached(eid)

        # If the user is not aiming to update the owner package of the resource
        # we need to verify he is granted to edit the current one.
        # Else the package_id is checked with respect to destination package
        # and the user's right to edit it.
        if "package_id" not in patch_data:
            patch_data["package_id"] = spec["package_id"]

        # If the user is trying to change the package_id, we need to ensure
        # that the package_type is also appropriately updated.
        patch_data["package_type"] = PackageEntity.resolve_type(spec["package_id"])

        authorize(patch_data["package_id"], patch_data["package_type"], "update")

        return self.patch(eid, patch_data)

    def track_lineage(self, resource_id: str, depth: Optional[int] = None):
        """Return the lineage of a resource. Thus meaning
        upon which task execution with which resource this artifact
        was created.
        """
        self.get_entity(resource_id)  # Ensure the resource exists and is accessible
        records = sql_utils.track_resource_lineage(resource_id, depth=depth)
        return (
            self.build_enriched_lineage_graph(
                lineage_records=records,
            )
            if records
            else {"nodes": [], "edges": []}
        )

    def build_enriched_lineage_graph(self, lineage_records: List[Dict]) -> Dict:
        nodes = {}
        edge_set = set()

        # Get the current (target) resource being tracked
        if not lineage_records:
            return {"nodes": [], "edges": []}

        current_resource_id = lineage_records[0]["resource_id"]
        current_resource_name = lineage_records[0].get(
            "current_resource_name", "Current Resource"
        )

        def add_node(node_id: str, label: str, node_type: str, extra: Dict = None):
            if node_id not in nodes:
                nodes[node_id] = {"id": node_id, "label": label, "type": node_type}
                if extra:
                    nodes[node_id].update(extra)

        for entry in lineage_records:
            # Input resource
            input_res_id = entry["input_resource_id"]
            input_res_label = entry.get("input_resource_name") or "Unnamed Resource"
            add_node(
                input_res_id,
                input_res_label,
                "Resource",
                {
                    "url": entry.get("input_resource_url"),
                    "package_id": entry.get("input_resource_package_id"),
                },
            )

            # Task
            task_id = entry["input_task_uuid"]
            task_name = entry.get("task_name") or "Unnamed Task"
            add_node(
                task_id,
                task_name,
                "Task",
                {
                    "process_id": entry.get("workflow_uuid"),
                    "state": entry.get("task_state"),
                    "start_date": entry.get("start_date"),
                    "end_date": entry.get("end_date"),
                    "image": entry.get("task_image", "remote"),
                },
            )

            # Output resource
            output_res_id = entry["resource_id"]
            task_alias = entry.get("output_name") or "Output Resource"
            global_name = entry.get("output_resource_name") or task_alias
            output_label = (
                f"{global_name} ({task_alias})"
                if global_name != task_alias
                else global_name
            )
            is_final = output_res_id == current_resource_id

            add_node(
                output_res_id,
                output_label,
                "Resource",
                {"final": True} if is_final else {},
            )
            # Edges (ensure uniqueness)
            edge_set.add((input_res_id, task_id))
            edge_set.add((task_id, output_res_id))

        return {
            "nodes": list(nodes.values()),
            "edges": list(edge_set),
            "current_resource_name": current_resource_name,
        }

    def track_forward_lineage(self, resource_id: str, depth: Optional[int] = None):
        self.get_entity(resource_id)  # Ensure the resource exists and is accessible
        records = sql_utils.track_resource_forward_lineage(resource_id, depth=depth)
        return (
            self.build_forward_enriched_lineage_graph(
                lineage_records=records,
            )
            if records
            else {"nodes": [], "edges": []}
        )

    def build_forward_enriched_lineage_graph(self, lineage_records: List[Dict]) -> Dict:
        nodes = {}
        edge_set = set()

        if not lineage_records:
            return {"nodes": [], "edges": [], "current_resource_name": None}

        # The resource being tracked (root resource)
        tracked_resource_id = lineage_records[0]["input_resource_id"]
        current_resource_name = lineage_records[0].get(
            "current_resource_name", "Tracked Resource"
        )

        def add_node(node_id: str, label: str, node_type: str, extra: Dict = None):
            if node_id not in nodes:
                nodes[node_id] = {"id": node_id, "label": label, "type": node_type}
                if extra:
                    nodes[node_id].update(extra)

        for entry in lineage_records:
            # Input resource node (may be the tracked resource or another input)
            input_res_id = entry["input_resource_id"]
            input_global_name = entry.get("input_resource_name") or "Unnamed Resource"
            add_node(
                input_res_id,
                input_global_name,
                "Resource",
                {
                    "url": entry.get("input_resource_url"),
                    "package_id": entry.get("input_resource_package_id"),
                    "final": input_res_id == tracked_resource_id,
                },
            )

            # Task node (output task uuid is the one being executed here)
            task_id = entry["task_uuid"]
            task_name = entry.get("task_name") or "Unnamed Task"
            add_node(
                task_id,
                task_name,
                "Task",
                {
                    "process_id": entry.get("workflow_uuid"),
                    "state": entry.get("task_state"),
                    "start_date": entry.get("start_date"),
                    "end_date": entry.get("end_date"),
                    "image": entry.get("task_image", "remote"),
                },
            )

            # Output resource node
            output_res_id = entry["output_resource_id"]
            output_name = entry.get("output_name") or "Output Resource"
            output_global_name = entry.get("output_resource_name") or output_name
            output_label = (
                f"{output_global_name} ({output_name})"
                if output_global_name != output_name
                else output_global_name
            )
            add_node(
                output_res_id,
                output_label,
                "Resource",
                {
                    "url": entry.get("output_resource_url"),
                    "package_id": entry.get("output_resource_package_id"),
                },
            )

            # Edges: input resource → task, task → output resource
            edge_set.add((input_res_id, task_id))
            edge_set.add((task_id, output_res_id))

        return {
            "nodes": list(nodes.values()),
            "edges": list(edge_set),
            "current_resource_name": current_resource_name,
        }

    def profile(self, id, profile_spec):
        """Profile a resource to extract metadata and other information.

        Args:
            profile_spec (dict): A dictionary containing the profiling parameters.

        Returns:
            dict: A dictionary containing the profiling results.
        """
        # Fetch the resource to evaluate authorization access
        r = self.get_entity(id)

        if not r.get("url").startswith("s3://") or not r.get("url").lower().endswith(
            (
                ".csv",
                ".xlsx",
                ".xls",
                ".txt",
                ".tif",
                ".tiff",
                ".img",
                ".vrt",
                ".nc",
                ".grd",
                ".asc",
                ".jp2",
                ".hdf",
                ".hdr",
                ".bil",
                ".png",
            )
        ):
            raise InvalidError(
                "Only S3 object URLs for tabular artifacts, image artifacts or text artifacts are supported for profiling."
            )

        # Decide the profile_type based on resource format and parameters
        resource_format = r.get("url").split(".")[-1].lower()

        if resource_format in ("csv", "xlsx", "xls"):
            profile_type = "tabular"

            delimiter = profile_spec.get("delimiter", None)
            header = profile_spec.get("header", 0)
            light_mode = profile_spec.get("light_mode", False)
            num_categorical_perc_threshold = profile_spec.get(
                "num_categorical_perc_threshold", 0.5
            )
            max_freq_distr = profile_spec.get("max_freq_distr", 10)
            is_timeseries = profile_spec.get("is_timeseries", False)
            timeseries_date_column = profile_spec.get("timeseries_date_column", None)

            crs = profile_spec.get("crs", "EPSG:4326")
            eps_distance = profile_spec.get("eps_distance", 1000)

            if is_timeseries and not timeseries_date_column:
                raise InvalidError(
                    "When is_timeseries is True, timeseries_date_column must be provided."
                )
            if is_timeseries:
                profile_type = "timeseries"

        elif resource_format in (
            "tif",
            "tiff",
            "img",
            "vrt",
            "nc",
            "grd",
            "asc",
            "jp2",
            "hdf",
            "hdr",
            "bil",
            "png",
        ):
            profile_type = "raster"
        elif resource_format in ("txt"):
            profile_type = "textual"
        else:
            raise InvalidError(
                "Unsupported resource format for profiling. Supported formats are: "
                "CSV, XLSX, XLS, TIF, TIFF, IMG, VRT, NC, GRD, ASC, JP2, HDF, HDR, BIL, PNG."
            )

        # Verify the data profiler tool is available in the KLMS
        try:
            TOOL.get_entity("data-profiler")
        except Exception:
            raise InvalidError(
                "Data Profiler tool is not available in the KLMS. Please ensure it is installed."
            )

        # Start a generic process for running the profiling task
        u = kutils.current_user().get("preferred_username", "anonymous")

        if u == "anonymous":
            raise InvalidError(
                "Data profiling requires a valid user session. Please log in to continue."
            )

        try:
            proc = PROCESS.create_entity(
                {
                    "name": "data-profiling-" + u,
                    "title": f"Data Profiling Workflow for {u}",
                    "tags": ["data-profiling", "profiling"],
                    "owner_org": "stelar-klms",
                }
            )
        except (ConflictError, InvalidError):
            # If the process already exists, we can reuse it
            proc = PROCESS.get_entity("data-profiling-" + u)
        except Exception as e:
            raise InternalException("Failed to create a profiling process.") from e

        # If the user has specified a destination package ID, use this.
        dest_package_id = r.get("package_id")
        if profile_spec.get("package_id", None):
            dest_package_id = profile_spec["package_id"]

        timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")

        # Build the task spec
        task_spec = {
            "process_id": proc.get("id"),
            "name": f"Data Profiling Task on {r.get('name', r.get('url').split('/')[-1])}",
            "tool": "data-profiler",
            "inputs": {"data": [r.get("id")]},
            "datasets": {"d0": str(dest_package_id)},
            "outputs": {
                "profile": {
                    "url": f"s3://klms-bucket/profiles/profile_{timestamp_str}_{r.get('id')}.json",
                    "resource": {
                        "name": f"Profile for {r.get('name', r.get('url').split('/')[-1])}",
                        "format": "json",
                        "relation": "profile",
                    },
                    "dataset": "d0",
                }
            },
            "parameters": {
                "profile_type": profile_type,
            },
        }

        if profile_type == "tabular" or profile_type == "timeseries":
            task_spec["parameters"].update(
                {
                    "sep": delimiter,
                    "header": header,
                    "light_mode": light_mode,
                    "num_cat_perc_threshold": num_categorical_perc_threshold,
                    "max_freq_distr": max_freq_distr,
                    "ts_mode": is_timeseries,
                    "time_column": timeseries_date_column,
                    "crs": crs,
                    "eps_distance": eps_distance,
                }
            )

        try:
            # Create the profiling task
            task = TASK.create_entity(task_spec)
        except Exception as e:
            raise InternalException("Failed to create the profiling task.") from e

        return {
            "task_id": task.get("id"),
            "process_id": proc.get("id"),
            "message": "Profiling task created successfully.",
        }

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
