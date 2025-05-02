import logging

from apiflask import APIBlueprint

import schema
from auth import security_doc, token_active
from backend.ckan import get_solr_schema
import utils
import kutils
from cutils import DATASET, GROUP, ORGANIZATION, RESOURCE, TAG, VOCABULARY
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
@catalog_bp.doc(tags=["Search Operations"])
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
