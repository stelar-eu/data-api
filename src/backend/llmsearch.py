import requests
import logging
import kutils
from flask import current_app
from functools import wraps

from typing import TYPE_CHECKING, Optional, Dict, Any
from urllib.parse import urljoin
from cutils import DATASET
from exceptions import (
    BackendError,
    BackendLogicError,
    AuthorizationError,
    DataError,
    InvalidError,
    NotFoundError,
)
from requests import Response
import kutils
from sql_utils import get_user_organizations_names


logger = logging.getLogger(__name__)


def llm_search_enabled(func):
    """Decorator that prevents method execution when LLM Search is disabled.

    It inspects the Flask application's configuration for the
    ``LLM_SEARCH_ENABLED`` flag and raises :class:`NotImplementedError`
    if the flag is not set to ``True``.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Access the real Flask application object and query the config flag
        app = current_app._get_current_object()
        config = app.config.get("settings", {})
        if not config.get("LLM_SEARCH_ENABLED", False):
            raise NotImplementedError(
                "LLM Search functionality is disabled via configuration."
            )
        return func(*args, **kwargs)

    return wrapper


class LLMSearchClient:
    """
    Client for interacting with the LLM Search service.
    """

    def __init__(self, endpoint_url: str):
        self.endpoint_url = endpoint_url
        self.default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @classmethod
    @llm_search_enabled
    def get_client(cls):
        """
        Create and return an LLMSearchClient instance using the Flask app context.
        """
        app = current_app._get_current_object()
        with app.app_context():
            config = app.config["settings"]
            endpoint_url = config["LLM_SEARCH_URL"]
            return cls(endpoint_url)

    @llm_search_enabled
    def raw_request(
        self,
        endpoint: str,
        *,
        json: Optional[dict] = None,
        method: str = "GET",
        headers: Dict[str, str] = {},
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        """
        Sends a request to the LLM Search API.

        Args:
            endpoint (str): The API endpoint (relative to `endpoint_url`). Can include query parameters.
            params (dict, optional): URL query parameters.
            json (dict, optional): JSON body to send in the request.
            headers (dict, optional): Additional headers to send with the request.
            **kwargs: Additional arguments to pass to the requests library.

        Returns:
            Response: The response object from the requests library.

        Raises:
            BackendError: If there is an error with the backend service.
            AuthorizationError: If authorization fails.
            DataError: If there is an error with the data.
            InvalidError: If the request is invalid.
            NotFoundError: If the resource is not found.
        """
        url = urljoin(self.endpoint_url, endpoint)
        headers = {**self.default_headers, **headers}

        try:
            logger.debug(f"Sending request to {url} with headers: {headers}")
            response = requests.request(
                method,
                url,
                json=json,
                headers=headers,
                params=params,
                **kwargs,
            )
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Error in LLM Search request: {e}")
            raise BackendError("Failed to communicate with LLM Search service") from e

    def raise_request_error(self, response: Response, context: dict):
        if response.status_code == 401:
            raise AuthorizationError("Authorization failed", detail=response.json())
        if response.status_code == 403:
            raise AuthorizationError("Authorization failed", detail=response.json())
        if response.status_code == 404:
            raise NotFoundError("Resource not found", detail=response.json())
        if response.status_code == 400:
            raise DataError("Bad request", detail=response.json())
        if response.status_code == 500:
            raise BackendLogicError("Backend error", detail=response.json())

        return response

    def _prepare_query(self, q_spec: dict) -> dict:
        q_spec = q_spec.copy()  # don't mutate caller's dict
        q_spec["auth_scope"] = get_user_organizations_names(
            kutils.current_user()["preferred_username"]
        ) + ["public"]
        q_spec["query"] = q_spec.pop("q", "")
        q_spec["n_results"] = q_spec.pop("limit", 10)
        return q_spec

    @llm_search_enabled
    def stream_request(
        self,
        endpoint: str,
        *,
        json: Optional[dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Dict[str, str] = {},
        **kwargs,
    ):
        """
        Open a streaming POST/GET to the LLM-Search service and return
        an iterator of raw bytes/str lines (already decoded).
        """
        hdrs = {
            **self.default_headers,
            **headers,
            "Accept": "text/event-stream",
        }

        resp = self.raw_request(
            endpoint,
            json=json,
            params=params,
            headers=hdrs,
            method="POST",
            stream=True,
            **kwargs,
        )
        # so handle status code directly here:
        if resp.status_code >= 400:
            self.raise_request_error(resp, context={})

        # requests.iter_lines keeps the \n delim intact if decode_unicode=True
        return resp.iter_lines(decode_unicode=True, chunk_size=1)

    @llm_search_enabled
    def send_request(
        self,
        endpoint: str,
        *,
        json: Optional[dict] = None,
        method: str = "GET",
        headers: Dict[str, str] = {},
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        """Make a request to the Quay Registry API and raise on error."""
        response = self.raw_request(
            endpoint=endpoint,
            json=json,
            method=method,
            headers=headers,
            params=params,
            **kwargs,
        )
        self.raise_request_error(response, context={})
        if response.status_code == 204:
            return True
        jsobj = response.json()
        return jsobj

    @llm_search_enabled
    def index(
        self,
        identifier: str,
        **kwargs,
    ):
        """
        Index a dataset in the ChromaDB of the LLM Search service.

        Args:
            identifier (dict): The unique identifier for the dataset to index.
        """

        dset = DATASET.get_entity(identifier)

        spec = {
            "dataset_id": dset["id"],
            "dataset_official_description": dset["notes"],
            "dataset_profile_description": "",
            "dataset_metadata": {
                "title": dset["title"],
                "creator": dset["author"],
                "organization": dset["organization"]["title"],
                "name": dset["name"],
                "tags": list(dset["tags"]),
                "auth_scope": [
                    "public" if not dset["private"] else dset["organization"]["name"]
                ],
            },
        }
        return self.send_request("/add_dataset", json=spec, method="POST")

    @llm_search_enabled
    def update(self, identifier: str, **kwargs):
        dset = DATASET.get_entity(identifier)

        spec = {
            "dataset_id": dset["id"],
            "dataset_official_description": dset["notes"],
            "dataset_profile_description": "",
            "dataset_metadata": {
                "title": dset["title"],
                "creator": dset["author"],
                "organization": dset["organization"]["title"],
                "name": dset["name"],
                "tags": list(dset["tags"]),
                "auth_scope": [
                    "public" if not dset["private"] else dset["organization"]["name"]
                ],
            },
        }
        return self.send_request("/update_dataset", json=spec, method="PUT")

    @llm_search_enabled
    def delete(self, identifier: str, **kwargs):
        """
        Delete a dataset from the LLM Search service.

        Args:
            identifier (str): The unique identifier for the dataset to delete.
        """
        dset = DATASET.get_entity(identifier)
        spec = {"dataset_id": dset["id"]}
        return self.send_request("/delete_dataset", json=spec, method="DELETE")

    @llm_search_enabled
    def search(
        self,
        **q_spec: Dict[str, Any],
    ):
        """
        Search the indexed datasets in the LLM Search service.

        Args:
            q_spec (dict): The search query specification.
        """
        payload = self._prepare_query(q_spec)
        dsets = self.send_request("/search_datasets", json=payload, method="POST")

        results = []
        for dset_id, score in dsets:
            try:
                dataset = DATASET.get_entity(dset_id)
                dataset["score"] = score
                results.append(dataset)
            except Exception as e:
                logger.warning(f"Failed to retrieve dataset {dset_id}: {e}")
        return results

    @llm_search_enabled
    def search_stream(self, **q_spec):
        payload = self._prepare_query(q_spec)
        return self.stream_request("/search_datasets_streaming", json=payload)


LLMSEARCH = LLMSearchClient.get_client
