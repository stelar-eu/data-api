from decimal import Decimal

from apiflask import Schema, fields, validators
from kubernetes.utils import parse_quantity


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
    image_pull_secret = fields.String(
        required=False, allow_none=True, validate=validators.Length(min=1)
    )
    cpu_request = fields.String(
        required=False,
        allow_none=True,
        validate=Quantity(),
    )
    cpu_limit = fields.String(required=False, allow_none=True, validate=Quantity())
    memory_request = fields.String(required=False, allow_none=True, validate=Quantity())
    memory_limit = fields.String(required=False, allow_none=True, validate=Quantity())
    ttl_seconds_after_finished = fields.Integer(
        required=False,
        allow_none=True,
    )


class JobProfile:
    """
    Metadata used to generate a Kubernetes job manifest for a task.
    """

    def __init__(self, tool_name: str, image: str, spec: dict):
        self.tool_name = tool_name
        self.image = image
        self.spec = spec

    def m_args(
        self, token: str, api_url: str, task_id: str, signature: str
    ) -> list[str]:
        """
        Returns the arguments to be passed to the container.
        """
        return [token, api_url, task_id, signature]

    def m_image_pull_policy(self) -> str:
        """
        Returns the image pull policy for the container.
        """
        return "Always"

    def m_image_pull_secrets(self) -> list[str]:
        """
        Returns the image pull secrets for the job.
        """
        return []

    def m_backoff_limit(self) -> int:
        """
        Returns the backoff limit for the job.
        """
        return 4

    def m_ttl_seconds_after_finished(self) -> int:
        """
        Returns the time to live (TTL) in seconds after the job is finished.
        """
        return 60 * 60 * 24

    def m_restart_policy(self) -> str:
        """
        Returns the restart policy for the job.
        """
        return "Never"

    def m_image(self) -> str:
        """
        Returns the image to be used for the job.
        """
        return "stelar/stelar-task-executor:latest"

    def manifest(self, token: str, api_url: str, task_id: str, signature: str):
        """
        Generates a Kubernetes job manifest for the task execution.


        Args:
            token (str): The authentication token for the API.
            api_url (str): The API URL via which the job will reach the STELAR API.
            task_id (str): The unique identifier for the task.
            signature (str): The signature for the task execution.
        Returns:
            V1Job: A Kubernetes job manifest.
        """
        from kubernetes.client import (
            V1Container,
            V1Job,
            V1JobSpec,
            V1LocalObjectReference,
            V1ObjectMeta,
            V1PodSpec,
            V1PodTemplateSpec,
        )

        # Determine if image requires credentials

        if tool_name.startswith("img.stelar.gr/stelar/"):
            image_pull_secrets = [V1LocalObjectReference(name="stelar-registry-secret")]
        elif tool_name.startswith("registry.minikube"):
            image_pull_secrets = [V1LocalObjectReference(name="quay-pull-secret")]
            quay_svc_host = os.getenv("QUAY_SERVICE_HOST")
            quay_svc_port = os.getenv("QUAY_SERVICE_PORT")
            quay_addr = f"{quay_svc_host}:{quay_svc_port}"
            tool_name = tool_name.replace("registry.minikube", quay_addr)

        jm = V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=V1ObjectMeta(
                name=f"stelar-task-{task_id}",
                labels={
                    "stelar.metadata.class": "task-execution",
                    "stelar.task-id": task_id,
                },
            ),
            spec=V1JobSpec(
                template=V1PodTemplateSpec(
                    metadata=V1ObjectMeta(
                        annotations={
                            "stelar/task-tool": tool_name,
                        },
                        labels={
                            "stelar.metadata.class": "task-execution",
                            "stelar.task-id": task_id,
                        },
                    ),
                    spec=V1PodSpec(
                        containers=[
                            V1Container(
                                name="main",
                                image=tool_name,
                                image_pull_policy=self.m_image_pull_policy(),
                                args=self.m_args(token, api_url, task_id, signature),
                            ),
                        ],
                        restart_policy=self.m_restart_policy,
                        image_pull_secrets=self.m_image_pull_secrets(),
                    ),
                ),
                backoff_limit=self.m_backoff_limit(),
                ttl_seconds_after_finished=self.m_ttl_seconds_after_finished(),  # 1 day
            ),
        )

        return jm
