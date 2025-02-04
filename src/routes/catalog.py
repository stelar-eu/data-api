import logging

from apiflask import APIBlueprint

from cutils import DATASET, GROUP, ORGANIZATION, RESOURCE, TAG, VOCABULARY
from routes.generic import generate_endpoints

logger = logging.getLogger(__name__)

catalog_bp = APIBlueprint("catalog_blueprint", __name__, tag="Data Catalog Operations")


# --------------------------------------------------------
#                    GENERATE ENDPOINTS
# --------------------------------------------------------

for e in [GROUP, ORGANIZATION, DATASET, RESOURCE, VOCABULARY, TAG]:
    logger.info(f"Generating endpoints for {e.name}")
    generate_endpoints(e, catalog_bp, logger)
