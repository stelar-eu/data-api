"""
Implementation of the Docker-based task execution engine
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import docker

from .engine import ExecEngine

if TYPE_CHECKING:
    from .engine import ExecEngineFactory


def configure(cfg: dict) -> ExecEngineFactory:
    """Configure a docker execution engine factory

    Args:
        engine_config (dict): Docker engine configuration
        cfg (dict): Full service configuration

    Returns:
        ExecEngineFactory: Docker ExecEngine factory
    """

    # N.B. This code has not been updated and it should be considered
    # deprecated.
    raise NotImplementedError(
        "Docker execution engine is deprecated and will be removed in the future. "
        "Use Kubernetes execution engine instead."
    )

    # Currently, there are no options to configure for the engine itself.
    # The api_url is available in cfg
    return DockerExecEngine(api_url=cfg["API_URL"]).factory


class DockerExecEngine(ExecEngine):
    """This is a very simple implementation of a docker execution engine.

    A single instance of this class is also a docker factory.

    Args:
        ExecEngine (_type_): _description_
    """

    def __init__(self, api_url):
        self.api_url = api_url

    def create_task(self, tool_name: str, token: str, task_id: str) -> str:
        # For now, just create a new client for each request. This seems safe even with
        # multiple threads.
        # TODO: re-examine this
        client = docker.from_env()
        container = client.containers.run(
            tool_name, [token, self.api_url, task_id], detach=True
        )

        return container.id

    def factory(self) -> ExecEngine:
        """This returns the object itself.

        Returns:
            ExecEngine: return itself as engine every time
        """
        return self
