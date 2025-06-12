import requests
from flask import current_app
import logging
import kutils

logger = logging.getLogger(__name__)


class OntopClient:
    def __init__(self, endpoint_url):
        """
        Initialize the SPARQL client with the endpoint URL.
        """
        self.endpoint_url = endpoint_url
        self.default_headers = {
            "Content-Type": "application/sparql-query",
            "Accept": "application/json",
        }

    @classmethod
    def get_client(cls):
        """
        Create and return an OntopClient instance using the Flask app context.
        """
        app = current_app._get_current_object()
        with app.app_context():
            config = app.config["settings"]
            endpoint_url = config["SPARQL_ENDPOINT"]
            return cls(endpoint_url)

    def execute_query(self, sparql_query):
        """
        Execute a SPARQL query against the endpoint with the specified user header.
        """
        headers = self.default_headers.copy()
        headers["x-user"] = kutils.current_user()["sub"]

        try:
            logger.debug(f"Sending SPARQL query with headers: {headers}")
            response = requests.post(
                self.endpoint_url, headers=headers, data=sparql_query
            )
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error executing SPARQL query: {e}")
            return None


# The Ontop client selector
ONTOP_CLIENT = OntopClient.get_client
