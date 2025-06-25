import requests
import logging
import kutils
from flask import current_app

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


logger = logging.getLogger(__name__)


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
    def get_client(cls):
        """
        Create and return an LLMSearchClient instance using the Flask app context.
        """
        app = current_app._get_current_object()
        with app.app_context():
            config = app.config["settings"]
            endpoint_url = config["LLM_SEARCH_URL"]
            return cls(endpoint_url)

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
        logger.debug(f"Indexing dataset with spec: {spec}")
        return self.send_request("/add_dataset", json=spec, method="POST")


LLMSEARCH = LLMSearchClient.get_client
