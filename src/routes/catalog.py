import logging

from apiflask import APIBlueprint

import schema
from auth import security_doc, token_active
from backend.ckan import get_solr_schema
from cutils import DATASET, GROUP, ORGANIZATION, RESOURCE, TAG, VOCABULARY
from routes.generic import error_responses, generate_endpoints, render_api_output

logger = logging.getLogger(__name__)

catalog_bp = APIBlueprint("catalog_blueprint", __name__, tag="Data Catalog Operations")


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
