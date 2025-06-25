import logging

from apiflask import APIBlueprint, Schema
from apiflask.fields import URL, Boolean, Dict, List
from apiflask.validators import OneOf
from flask import request
from auth import security_doc, token_active, admin_required
from routes.generic import error_responses, generate_endpoints, render_api_output
from backend.llmsearch import LLMSEARCH

logger = logging.getLogger(__name__)

llmsearch_bp = APIBlueprint(
    "llmsearch_blueprint",
    __name__,
    tag="LLM Accelerated Search Operations",
)


@llmsearch_bp.post("/index/<dataset_id>")
@token_active
@admin_required
@render_api_output(logger)
def api_llm_index_dataset(dataset_id: str):
    """
    Index a dataset for LLM accelerated search.
    """
    return LLMSEARCH().index(dataset_id)
