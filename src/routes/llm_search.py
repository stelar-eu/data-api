import logging

from apiflask import APIBlueprint
from flask import Response, stream_with_context
from auth import security_doc, token_active, admin_required
from routes.generic import render_api_output
from backend.llmsearch import LLMSEARCH, llm_search_enabled
from schema import LLMSearchQuery

logger = logging.getLogger(__name__)

llmsearch_bp = APIBlueprint(
    "llmsearch_blueprint",
    __name__,
    tag="LLM Accelerated Search Operations",
)


@llmsearch_bp.post("/<dataset_id>")
@llmsearch_bp.doc(
    security=security_doc,
    summary="Index a dataset for LLM accelerated search ma",
    description="Index a dataset for LLM accelerated search. This operation requires admin privileges.",
)
@llm_search_enabled
@token_active
@admin_required
@render_api_output(logger)
def api_llm_index_dataset(dataset_id: str):
    """
    Index a dataset for LLM accelerated search.
    """
    return LLMSEARCH().index(dataset_id)


@llmsearch_bp.put("/<dataset_id>")
@llmsearch_bp.doc(
    security=security_doc,
    summary="Update a dataset in LLM accelerated search",
    description="Update a dataset in LLM accelerated search. This operation requires admin privileges.",
)
@llm_search_enabled
@token_active
@admin_required
@render_api_output(logger)
def api_llm_update_dataset(dataset_id: str):
    """
    Update a dataset in LLM accelerated search.
    """
    return LLMSEARCH().update(dataset_id)


@llmsearch_bp.delete("/<dataset_id>")
@llmsearch_bp.doc(
    security=security_doc,
    summary="Delete a dataset from LLM accelerated search",
    description="Delete a dataset from LLM accelerated search. This operation requires admin privileges.",
)
@llm_search_enabled
@token_active
@admin_required
@render_api_output(logger)
def api_llm_delete_dataset(dataset_id: str):
    """
    Delete a dataset from LLM accelerated search.
    """
    return LLMSEARCH().delete(dataset_id)


@llmsearch_bp.post("/search")
@llmsearch_bp.input(LLMSearchQuery, location="json")
@llmsearch_bp.doc(
    security=security_doc,
    summary="Search using LLM accelerated search",
    description="Search using LLM accelerated search. This operation requires a valid token.",
)
@llm_search_enabled
@token_active
@render_api_output(logger)
def api_llm_search(json_data):
    """
    Search using LLM accelerated search.
    """
    return LLMSEARCH().search(**json_data)


@llmsearch_bp.post("/search/stream")
@llmsearch_bp.input(LLMSearchQuery, location="json")
@llmsearch_bp.doc(
    security=security_doc,
    summary="Stream search results using LLM accelerated search",
    description="Stream search results using LLM accelerated search. This operation requires a valid token.",
)
@llm_search_enabled
@token_active
def api_llm_search_stream(json_data):
    down_iter = LLMSEARCH().search_stream(**json_data)

    def relay():
        for line in down_iter:
            if line:
                yield line + "\n"

    return Response(
        stream_with_context(relay()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
