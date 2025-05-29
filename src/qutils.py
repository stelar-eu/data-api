import logging
from backend.registry import quay_request
from exceptions import (
    NotFoundError,
)

logger = logging.getLogger(__name__)


class QuayClient:
    """
    A singleton class to interact with the Quay Registry API.
    This class provides methods to get repository information, tags, manifests,
    and delete repositories or tags.
    It also provides methods to generate, get, and revoke application tokens.
    The class uses the singleton pattern to ensure that only one instance of the
    class exists throughout the application.

    Utilizes the `quay_request` function to send requests to the Quay API from the
    `backend.registry` module.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(QuayClient, cls).__new__(cls)
        return cls._instance

    def get_repository(self, repository: str):
        """
        Get the repository information from Quay.

        Args:
            repository (str): The name of the repository.

        Returns:
            dict: The repository information.
        """
        endpoint = f"/repository/stelar/{repository}"
        response = quay_request(endpoint, method="GET")
        return response

    def create_repository(self, repository: str, notes: str = ""):
        """
        Create a new repository in Quay.

        Args:
            repository (str): The name of the repository.

        Returns:
            dict: The response from the Quay API.
        """
        payload = {
            "namespace": "stelar",
            "repository": repository,
            "visibility": "private",
            "description": notes,
            "repo_kind": "image",
        }
        endpoint = "/repository"
        response = quay_request(endpoint, json=payload, method="POST")
        return response

    def get_repository_tags(self, repository: str):
        """
        Get the tags of a repository from Quay.

        Args:
            repository (str): The name of the repository.

        Returns:
            dict: The tags of the repository.
        """
        endpoint = f"/repository/stelar/{repository}/tag/?onlyActiveTags=true"
        response = quay_request(endpoint=endpoint, method="GET")
        return response["tags"] if "tags" in response else []

    def get_hashes(self, repository: str):
        """
        Get the manifest hashes of tags for a repository from Quay.

        Args:
            repository (str): The name of the repository.
            tag (str): The tag of the repository.

        Returns:
            dict: The manifest of the repository.
        """
        tags = self.get_repository_tags(repository)

        hashes = {}
        for manifest in tags:
            hashes[manifest["name"]] = manifest["manifest_digest"]

        return hashes

    def get_manifest(self, repository: str, tag: str):
        """
        Get the manifest of a tag for a repository from Quay.

        Args:
            repository (str): The name of the repository.
            tag (str): The tag of the repository.

        Returns:
            dict: The manifest of the repository.
        """
        tag_hashes = self.get_hashes(repository)
        if tag not in tag_hashes:
            raise NotFoundError(f"Tag {tag} not found in repository {repository}")

        endpoint = f"/repository/stelar/{repository}/manifest/{tag_hashes[tag]}"
        response = quay_request(endpoint, method="GET")
        return response

    def delete_repository(self, repository: str):
        """
        Delete a repository from Quay.

        Args:
            repository (str): The name of the repository.

        Returns:
            dict: The response from the Quay API.
        """
        endpoint = f"/repository/stelar/{repository}"
        response = quay_request(endpoint, method="DELETE")
        return response

    def delete_tag(self, repository: str, tag: str):
        """
        Delete a tag from a repository in Quay.

        Args:
            repository (str): The name of the repository.
            tag (str): The tag of the repository.

        Returns:
            dict: The response from the Quay API.
        """
        endpoint = f"/repository/stelar/{repository}/tag/{tag}"
        response = quay_request(endpoint, method="DELETE")
        return response

    def generate_app_token(self, title: str) -> str:
        """
        Generate an application token for the current user in Quay.
        Args:
            title (str): The title of the application token.
        Returns:
            str: The application token.
        """
        endpoint = "/user/apptoken"
        data = {
            "title": title,
        }
        response = quay_request(endpoint, method="POST", json=data)
        if "token" in response:
            response["token"]["id"] = response["token"].pop("uuid")
        return response["token"] if "token" in response else response

    def get_app_tokens(self) -> list:
        """
        Get all application tokens for the current user in Quay.
        Returns:
            list: A list of application tokens.
        """
        endpoint = "/user/apptoken"
        response = quay_request(endpoint, method="GET")
        if "tokens" in response:
            tokens = {}
            for token in response["tokens"]:
                tokens[token["uuid"]] = token
                tokens[token["uuid"]].pop("uuid")
            return tokens
        return response

    def get_app_token(self, token_id: str) -> dict:
        """
        Get an application token for the current user in Quay.
        Args:
            token_id (str): The ID of the application token.

        Returns:
            dict: The application token.
        """
        endpoint = f"/user/apptoken/{token_id}"
        response = quay_request(endpoint, method="GET")
        return response["token"] if "token" in response else response

    def revoke_app_token(self, token_id: str):
        """
        Revoke an application token for the current user in Quay.
        Args:
            token_id (str): The ID of the application token.

        Returns:
            None
        """
        endpoint = f"/user/apptoken/{token_id}"
        quay_request(endpoint, method="DELETE")

        return {"id": token_id}

    def sync_user_permissions(self, user: dict):
        """
        Sync the permissions of a user in Quay.

        Args:
            user (dict): The representation of the user updated permissions.

            Example:
                {
                    "oauth_id": "<UUID>",
                    "username": "example",
                    "email": "example@example.com",
                    "groups": ["pushers"]
                }
        Returns:
            dict: The response from the Quay API.
        """
        endpoint = "/user/"
        response = quay_request(endpoint, method="PATCH", json=user)
        return response


REGISTRY = QuayClient()
