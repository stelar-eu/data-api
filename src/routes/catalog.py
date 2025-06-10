import logging

from apiflask import APIBlueprint, Schema
from apiflask.fields import URL, Boolean, Dict, List
from apiflask.validators import OneOf

import schema
from auth import security_doc, token_active
from backend.ckan import get_solr_schema
import utils
import kutils
from backend.ckan import ALL_RELATIONSHIPS, get_solr_schema
from cutils import (
    DATASET,
    GROUP,
    ORGANIZATION,
    RESOURCE,
    TAG,
    VOCABULARY,
)
from licenses import (
    LICENSE,
    LicenseSchema,
    LicenseUpdateSchema,
)
from exceptions import DataError
from package import (
    create_relationship,
    delete_relationship,
    get_relationships,
    update_relationship,
)
from routes.generic import error_responses, generate_endpoints, render_api_output

logger = logging.getLogger(__name__)

catalog_bp = APIBlueprint(
    "catalog_blueprint", __name__, tag="RESTful Publishing Operations"
)


# --------------------------------------------------------
#                    GENERATE ENDPOINTS
# --------------------------------------------------------

for e in [GROUP, ORGANIZATION, DATASET, RESOURCE, VOCABULARY, TAG]:
    logger.info(f"Generating endpoints for {e.name}")
    generate_endpoints(e, catalog_bp, logger)


# Add endpoint for obtaining the SOLR schema
@catalog_bp.get("/search/schema")
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(
    summary="Retrieve the Solr schema used for searching the Data Catalog",
    description="""\
This endpoint returns the Solr schema used for searching the Data Catalog. Using this schema,
tools can be built to compose catalog search queries automatically.
For  detailed information on the Sorl schema, refer to the Solr documentation.
    """,
    tags=["RESTful Search Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_get_search_shema():
    return get_solr_schema()


@catalog_bp.route("/export/zenodo/<dataset_id>", methods=["GET"])
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(tags=["RESTful Publishing Operations"])
@token_active
@render_api_output(logger)
def api_export_zenodo_dataset_id(dataset_id):
    """Export all metadata available for a dataset in order to published to Zenodo.

    Args:
        id: The unique identifier of the dataset as listed in CKAN.

    Returns:
        A JSON with metadata compliant with DataCite's Metadata Schema employed by Zenodo.
    """
    # Formulate metadata according to Zenodo specifications; no DOI specified
    dset = DATASET.get_entity(dataset_id)
    return utils.prepareZenodoMetadata(
        dset,
        kutils.get_user(dset["creator_user_id"])["fullname"],
        dset["organization"]["title"],
        None,
    )


@catalog_bp.route("/resource/<entity_id>/lineage", methods=["GET"])
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(tags=["Search Operations"])
@token_active
@render_api_output(logger)
def api_get_resource_lineage(entity_id):
    """Get the lineage of a resource.

    Args:
        entity_id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the lineage of the resource.
    """
    return RESOURCE.track_lineage(entity_id)


#
# Relationship endpoints
#


class RelationshipListResponse(Schema):
    help = URL(required=True)
    success = Boolean(required=True)

    # Use fields that are conditionally required depending on success
    result = List(Dict(), required=False)


ANYREL = "_"


@catalog_bp.get("/relationships/<subid>", defaults={"objid": None, "rel": ANYREL})
@catalog_bp.get("/relationships/<subid>/<rel>", defaults={"objid": None})
@catalog_bp.get("/relationships/<subid>/<rel>/<objid>")
@catalog_bp.output(RelationshipListResponse, status_code=200)
@catalog_bp.doc(
    summary="Retrieve relationships between entities",
    description="""\
This endpoint retrieves relationships between package-based entities in the Data Catalog.
The relationships are defined in the CKAN data model. The relationships are stored in the
CKAN database and are used to establish connections between different entities, such as datasets,
workflows, processes and tools.
""",
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([400, 401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_get_relationships(subid, objid, rel):
    """Retrieve relationships between entities"""
    if rel == ANYREL:
        rel = None
    if rel is not None and rel not in ALL_RELATIONSHIPS:
        raise DataError(f"Invalid relationship type: {rel}")
    return get_relationships(subid, objid, rel)


class RelationshipComment(Schema):
    """Schema for the relationship comment."""

    comment: str = schema.String(
        metadata={
            "description": "Comment or description of the relationship",
            "example": "This is a comment",
        },
        required=False,
        load_default=None,
    )


@catalog_bp.post("/relationship/<subid>/<rel>/<objid>")
@catalog_bp.input(RelationshipComment, location="json")
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(
    summary="Create a relationship between package entities",
    description="""\
This endpoint creates a relationship between two package entities in the Data Catalog.
If the relationship already exists, it will be updated (w/ the new comment).
If the relationship does not exist, it will be created.
""",
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_create_relationship(subid, objid, rel, json_data):
    """Retrieve relationships between entities"""
    comment = json_data.get("comment", None)
    if rel not in ALL_RELATIONSHIPS:
        raise DataError(f"Invalid relationship type: {rel}")
    return create_relationship(subid, objid, rel, comment)


@catalog_bp.put("/relationship/<subid>/<rel>/<objid>")
@catalog_bp.input(RelationshipComment, location="json")
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(
    summary="Update a relationship comment",
    description="""\
This endpoint updates a relationship between two package entities in the Data Catalog.
If the relationship does not exist, a NotFound error will be raised.
Only the comment can be updated.
""",
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_update_relationships(subid, objid, rel, json_data):
    """Retrieve relationships between entities"""
    comment = json_data.get("comment", None)
    if rel not in ALL_RELATIONSHIPS:
        raise DataError(f"Invalid relationship type: {rel}")
    return update_relationship(subid, objid, rel, comment)


@catalog_bp.delete("/relationship/<subid>/<rel>/<objid>")
@catalog_bp.output(schema.DeleteResponse, status_code=200)
@catalog_bp.doc(
    summary="Delete a relationship between package entities",
    description="""\
This endpoint deletes a relationship between two package entities in the Data Catalog,
if it exists. It is not an error to delete a relationship that does not exist.
""",
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_delete_relationships(subid, objid, rel):
    """Retrieve relationships between entities"""
    if rel not in ALL_RELATIONSHIPS:
        raise DataError(f"Invalid relationship type: {rel}")
    return delete_relationship(subid, objid, rel)


#
# License endpoints
#


@catalog_bp.get("/licenses")
@catalog_bp.output(schema.IdListResponse, status_code=200)
@catalog_bp.doc(
    summary="Retrieve all licenses Keys available in the Data Catalog",
    description="""\This endpoint retrieves all licenses available in the Data Catalog.
    The licenses are used to define the terms of use for datasets, resources, and other entities in the catalog.
    """,
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_get_licenses():
    """Retrieve all licenses available in the Data Catalog."""
    return LICENSE.list_entities()


@catalog_bp.get("/licenses.fetch")
@catalog_bp.output(schema.EntityListResponse, status_code=200)
@catalog_bp.doc(
    summary="Fetch all licenses available in the Data Catalog",
    description="""\This endpoint retrieves all licenses available in the Data Catalog.
    The licenses are used to define the terms of use for datasets, resources, and other entities in the catalog.
    """,
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_fetch_licenses():
    """Retrieve all licenses available in the Data Catalog."""
    return LICENSE.fetch_entities()


@catalog_bp.get("/license/<entity_id>")
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(
    summary="Retrieve a license by its unique identifier",
    description="""\
This endpoint retrieves a license by its unique identifier.
    The license is used to define the terms of use for datasets, resources, and other entities in the catalog.
    """,
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 404, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_get_license(entity_id):
    """Retrieve a license by its unique identifier."""
    return LICENSE.get(entity_id)


@catalog_bp.post("/license")
@catalog_bp.input(LicenseSchema, location="json")
@catalog_bp.output(schema.APIResponse, status_code=201)
@catalog_bp.doc(
    summary="Create a new license",
    description="""\
This endpoint creates a new license in the Data Catalog.
    The license is used to define the terms of use for datasets, resources, and other entities in the catalog.
    """,
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([400, 401, 403, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_create_license(json_data):
    """Create a new license in the Data Catalog."""
    return LICENSE.create(**json_data)


@catalog_bp.patch("/license/<entity_id>")
@catalog_bp.input(LicenseUpdateSchema(partial=True), location="json")
@catalog_bp.output(schema.APIResponse, status_code=200)
@catalog_bp.doc(
    summary="Patch an existing license",
    description="""\
This endpoint patches an existing license in the Data Catalog.
    The license is used to define the terms of use for datasets, resources, and other entities in the catalog.
    """,
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([400, 401, 403, 404, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_patch_license(entity_id, json_data):
    """Patch an existing license in the Data Catalog."""
    return LICENSE.patch(entity_id, **json_data)


@catalog_bp.delete("/license/<entity_id>")
@catalog_bp.output(schema.DeleteResponse, status_code=200)
@catalog_bp.doc(
    summary="Delete a license by its unique identifier",
    description="""\
This endpoint deletes a license by its unique identifier.
    The license is used to define the terms of use for datasets, resources, and other entities in the catalog.
    """,
    tags=["RESTful Publishing Operations"],
    security=security_doc,
    responses=error_responses([401, 403, 404, 500, 502]),
)
@token_active
@render_api_output(logger)
def api_delete_license(entity_id):
    """Delete a license by its unique identifier."""
    return LICENSE.delete(entity_id)
