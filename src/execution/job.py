from __future__ import annotations

import logging
import re
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from apiflask import Schema, fields, validators
from kubernetes.client import (
    V1Container,
    V1Job,
    V1JobSpec,
    V1LocalObjectReference,
    V1ObjectMeta,
    V1PodSpec,
    V1PodTemplateSpec,
    V1ResourceRequirements,
)
from kubernetes.utils import parse_quantity

if TYPE_CHECKING:
    from .kubernetes import K8sExecEngine

logger = logging.getLogger(__name__)

KUBERNETES_NAME_PATTERN = re.compile(
    r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
)


class Quantity(validators.Validator):
    """
    Parses a quantity string and returns a formatted string.
    """

    def check_quantity(self, dval: Decimal):
        return True

    def __call__(self, value):
        try:
            self.check_quantity(parse_quantity(value))
            return value
        except ValueError as e:
            raise validators.ValidationError(f"Invalid quantity: {value}") from e


class JobProfileSchema(Schema):
    image = fields.String(required=False, validate=validators.Length(min=1))

    # spec = fields.Dict(required=True, keys=fields.String(), values=fields.Raw())
    description = fields.String(required=False, allow_none=True)

    image_pull_policy = fields.String(
        required=False,
        validate=validators.OneOf(["Always", "IfNotPresent", "Never"]),
        allow_none=True,
    )
    image_pull_secrets = fields.List(
        fields.String(validate=validators.Length(min=1)),
        required=False,
        allow_none=True,
        validate=validators.Length(min=0),
    )
    cpu_request = fields.String(
        required=False,
        allow_none=True,
        validate=Quantity(),
    )
    cpu_limit = fields.String(required=False, allow_none=True, validate=Quantity())
    memory_request = fields.String(required=False, allow_none=True, validate=Quantity())
    memory_limit = fields.String(required=False, allow_none=True, validate=Quantity())

    backoff_limit = fields.Integer(
        required=False,
        allow_none=True,
        validate=validators.Range(min=0, max=10),
    )

    restart_policy = fields.String(
        required=False,
        allow_none=True,
        validate=validators.OneOf(["Always", "OnFailure", "Never"]),
    )

    ttl_seconds_after_finished = fields.Integer(
        required=False,
        allow_none=True,
    )


def chain(key: str, *d) -> Any:
    """
    Chain-search a key with a list of dictionaries.

    This call accepts a key and a sequence of values, all dicts except
    possibly the last one.

    It will search for the key in each dictionary in the sequence,
    returning the value for the key in the first dictionary that contains
    it, or the first item in the sequence if it is not a dictionary.

    If the key is not found in any of the dictionaries, it returns None.

    Args:
        key (str): The key to search for.
        *d: A sequence of dictionaries or values.

    Returns:
        The value associated with the key in the first dictionary that contains it,
        or the first item if it is not a dictionary, or None if not found.
    """
    for item in d:
        if isinstance(item, dict):
            if key in item:
                return item[key]
            else:
                continue
        else:
            return item
    return None


class JobSpec:
    """
    Metadata used to generate a Kubernetes job manifest for a task.
    """

    def __init__(self, tool_name: str, image: str, profile: dict, task_info: dict):
        self.tool_name = tool_name
        self.image = image
        self.profile = profile
        self.task_info = task_info

    # -----------------------------------
    # Manifest creation
    # -----------------------------------

    def m_args(self, engine: K8sExecEngine) -> list[str]:
        """
        Returns the arguments to be passed to the container.
        """
        token = "Bearer " + self.task_info["token"]
        api_url = engine.api_url
        task_id = self.task_info["id"]
        signature = self.task_info["signature"]
        return [token, api_url, task_id, signature]

    def m_image_pull_policy(self, engine: K8sExecEngine) -> str:
        """
        Returns the image pull policy for the container.
        """
        return chain("image_pull_policy", self.profile, engine.default_profile)

    def m_image_pull_secrets(
        self, engine: K8sExecEngine
    ) -> list[V1LocalObjectReference]:
        """
        Merge the image pull secrets for the job.
        """

        l1 = self.profile.get("image_pull_secrets", [])
        l2 = engine.default_profile.get("image_pull_secrets", [])
        return [
            V1LocalObjectReference(name=name) for name in set(l1 + l2)
        ]  # Merge and remove duplicates

    def m_backoff_limit(self, engine: K8sExecEngine) -> int:
        """
        Returns the backoff limit for the job.
        """
        return chain("backoff_limit", self.profile, engine.default_profile)

    def m_ttl_seconds_after_finished(self, engine: K8sExecEngine) -> int:
        """
        Returns the time to live (TTL) in seconds after the job is finished.
        """
        return chain("ttl_seconds_after_finished", self.profile, engine.default_profile)

    def m_restart_policy(self, engine: K8sExecEngine) -> str:
        """
        Returns the restart policy for the job.
        """
        return chain("restart_policy", self.profile, engine.default_profile)

    def m_image(self, engine: K8sExecEngine) -> str:
        """
        Returns the image to be used for the job.
        """
        return engine.image_spec(self.image)

    def m_labels(self, engine: K8sExecEngine) -> dict:
        """
        Returns the labels to be applied to the job.
        """
        return {
            "stelar.metadata.class": "task-execution",
            "stelar.task-id": self.task_info["id"],
            "stelar.tool-name": str(self.tool_name),
            "stelar.creator": self.task_info["creator"],
            "stelar.process-id": self.task_info["process_id"],
        }

    def m_resources(self, engine: K8sExecEngine) -> V1ResourceRequirements | None:
        cpu_request = chain("cpu_request", self.profile, engine.default_profile)
        cpu_limit = chain("cpu_limit", self.profile, engine.default_profile)
        memory_request = chain("memory_request", self.profile, engine.default_profile)
        memory_limit = chain("memory_limit", self.profile, engine.default_profile)

        req = {}
        if cpu_request is not None:
            req["cpu"] = cpu_request
        if memory_request is not None:
            req["memory"] = memory_request
        limits = {}
        if cpu_limit is not None:
            limits["cpu"] = cpu_limit
        if memory_limit is not None:
            limits["memory"] = memory_limit

        res = {}
        if req:
            res["requests"] = req
        if limits:
            res["limits"] = limits

        if res:
            return V1ResourceRequirements(**res)
        else:
            return None

    def m_name(self, engine: K8sExecEngine) -> str:
        """
        Returns the name of the job.
        The name must be a DNS subdomain compliant string.
        """
        # Kubernetes job names must be DNS subdomain compliant
        # https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names
        # Try to generate a name from the tool name, and check if it is valid, fall back to a safe one.
        conv_name = self.tool_name.replace("_", "-")
        jobname = f"task-{self.task_info['id']}-{conv_name}"

        # Check if the name is valid
        if KUBERNETES_NAME_PATTERN.fullmatch(jobname):
            return jobname
        else:
            return f"task-{self.task_info['id']}"

    def m_annotations(self, engine: K8sExecEngine) -> dict:
        """
        Returns the annotations to be applied to the job.
        """
        return {
            "stelar/tool-name": str(self.tool_name),
            "stelar/image": str(self.image),
            "stelar/api_url": engine.api_url,
            "stelar/tool-profile": self.task_info["profile"],
        }

    def manifest(self, engine: K8sExecEngine) -> V1Job:
        """
        Generates a Kubernetes job manifest for the task execution.

        Args:
            engine (K8sExecEngine): The Kubernetes execution engine instance.
        Returns:
            V1Job: A Kubernetes job manifest.
        """

        logger.debug("Generating manifest")
        logger.debug("Tool name = %s", self.tool_name)
        logger.debug("Image = %s", self.image)
        logger.debug("Profile = %s", self.profile)
        logger.debug("Default profile = %s", engine.default_profile)
        logger.debug("Task info = %s", self.task_info)

        self.tool_name
        task_id = self.task_info["id"]

        jm = V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=V1ObjectMeta(
                name=self.m_name(engine),
                labels=self.m_labels(engine),
                annotations=self.m_annotations(engine),
            ),
            spec=V1JobSpec(
                template=V1PodTemplateSpec(
                    metadata=V1ObjectMeta(
                        annotations=self.m_annotations(engine),
                        labels=self.m_labels(engine),
                    ),
                    spec=V1PodSpec(
                        containers=[
                            V1Container(
                                name="main",
                                image=self.m_image(engine),
                                image_pull_policy=self.m_image_pull_policy(engine),
                                args=self.m_args(engine),
                                resources=self.m_resources(engine),
                            ),
                        ],
                        restart_policy=self.m_restart_policy(engine),
                        image_pull_secrets=self.m_image_pull_secrets(engine),
                    ),
                ),
                backoff_limit=self.m_backoff_limit(engine),
                ttl_seconds_after_finished=self.m_ttl_seconds_after_finished(engine),
            ),
        )

        return jm
