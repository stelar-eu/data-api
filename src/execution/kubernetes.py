"""
Implementation of the Kubernetes-based task execution engine.

 - In this implementation each task is executed as a job.
 - All jobs are created in a designated namespace. If not given,
   the namespace of the service itself is given (from environment)
 - Each job is labeled with the task_id, tool name, etc.

A sample config:

```
execution:
    engine: kubernetes
    namespace: playground
```

Note that, in order for this module to be able to execute incluster
(create jobs etc), a service account with the required permissions
should be given the appropriate permissions.

TODOs:
    - support execution when service itself is not on K8s,
      e.g. service runs in docker but executes jobs on k8s

"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

import kubernetes as k8s
from kubernetes.client.rest import ApiException

from .engine import ExecEngine
from .job import JobSpec

if TYPE_CHECKING:
    from .engine import ExecEngineFactory


# Default logger for this module
logger = logging.getLogger("exec")


def kubernetes_client_config(engine_config):
    """Configure kubernetes client.

    Args:
        engine_config (_type_): _description_
    """
    config = engine_config.get("config", "incluster")

    match config:
        case "incluster":
            logger.info("Loading kubernetes incluster config.")
            k8s.config.load_incluster_config()
        case "kubeconfig":
            logger.info("Loading kubernetes from kube config.")
            k8s.config.load_kube_config()

        case _:
            raise ValueError(f"Kubernetes client config not understood: {config}")


def configure(cfg: dict, client_config=True) -> ExecEngineFactory:
    """Configure a Kubernetes execution engine factory

    Args:
        cfg (dict): Deployment configuration
        client_config (bool, optional): If true, configure the kubernetes client.
                Defaults to True. It may be set to False for testing.
    Returns:
        ExecEngineFactory: Docker ExecEngine factory
    """

    # Initialize k8s configuration
    engine_config = cfg["execution"]
    if engine_config["engine"] != "kubernetes":
        raise ValueError("Execution engine is not 'kubernetes'")

    if client_config:
        kubernetes_client_config(engine_config)

    # Get execution namespace from engine config.
    # Else, raise an exception.
    nspace = engine_config.get("namespace", None)
    if nspace is None:
        raise RuntimeError("Execution namespace undefined")
    logger.info("Established namespace %s for task execution", nspace)

    api_url = engine_config.get("api_url", None)
    if api_url is None:
        raise RuntimeError("API URL for task execution not defined in config")
    else:
        logger.info("Established API URL %s for task execution", api_url)

    # Get registry address from engine config, if available
    registry_address = engine_config.get("image_registry_address", None)
    if registry_address is None:
        logger.warning("Image registry address not defined in config, using default.")
    else:
        logger.info(
            "Established registry address %s for task execution", registry_address
        )

    # Get registry organization from engine config, if available
    registry_org = engine_config.get("image_registry_org", "stelar")
    if registry_org is None:
        logger.warning(
            "Image registry organization not defined in config, using default."
        )
    else:
        logger.info(
            "Established registry organization %s for task execution", registry_org
        )

    default_specs = engine_config.get(
        "default_specs",
        {
            "image_pull_policy": "Always",
            "image_pull_secrets": ["stelar-registry-secret"],
            "ttl_seconds_after_finished": 60 * 60 * 24,
            "backoff_limit": 3,
            "restart_policy": "Never",
        },
    )

    # Define the factory function in here
    def factory() -> ExecEngine:
        # The api_url is available in cfg
        logger.info("Created kubernetes task execution engine.")
        return K8sExecEngine(
            api_url=api_url,
            namespace=nspace,
            registry_address=registry_address,
            registry_org=registry_org,
            default_specs=default_specs,
        )

    logger.info("Created kubernetes exec engine factory")
    logging.getLogger("kubernetes.client.rest").setLevel(logging.WARNING)
    return factory


class K8sExecEngine(ExecEngine):
    """The Kubernetes execution engine.

    A single instance of this class is also a docker factory.

    Args:
        ExecEngine (_type_): _description_
    """

    def __init__(
        self, api_url, namespace, registry_address, registry_org, default_specs
    ):
        self.api_url = api_url
        self.namespace = namespace
        self.registry_address = registry_address
        self.registry_org = registry_org
        self.default_specs = default_specs
        self.v1 = k8s.client.CoreV1Api()
        self.batch = k8s.client.BatchV1Api()

    def default_spec(self, spec_name) -> Any:
        """Get the default specification for a given spec name.

        Args:
            spec_name (str): The name of the specification to retrieve.

        Returns:
            Any: The default specification value, or None if not found.
        """
        return self.default_specs.get(spec_name, None)

    def image_spec(self, tool_image: str) -> str:
        """Get the image spec for a tool image.

        A tool image string is expected to look like:
        `tool_name:tag`. The method will return the full image spec,
        suitable for pulling from the configured registry.

        However, it is possible that the tool image already includes
        the full registry address and organization, in which case
        it will be returned as is.

        Args:
            tool_image (str): The tool image string.

        Returns:
            str: The full image name including registry address and organization.
        """
        if re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+(:[0-9]+)?//", tool_image):
            return tool_image
        else:
            return f"{self.registry_address}/{self.registry_org}/{tool_image}"

    def fetch_task_logs(self, task_id: str) -> dict:
        """Fetch logs for all pods associated with a specific stelar.task-id.

        Args:
            task_id (str): The task ID to filter pods by.

        Returns:
            dict: A dictionary containing pod names and their respective logs.
        """
        label_selector = f"stelar.task-id={task_id}"
        logs = {}

        try:
            # Get all pods for the given task_id
            pods = self.v1.list_namespaced_pod(
                namespace=self.namespace, label_selector=label_selector
            )

            # Iterate over the pods and fetch logs, unless the pod status is "Pending"
            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_status = (
                    pod.status.phase
                )  # Get pod status (e.g., Pending, Running, Succeeded, Failed)

                # Fetch logs only if the pod is not in Pending status
                if pod_status != "Pending":
                    try:
                        log = self.v1.read_namespaced_pod_log(
                            name=pod_name, namespace=self.namespace, container="main"
                        )
                        logs[pod_name] = log
                    except ApiException as e:
                        logger.error("Failed to fetch logs for pod %s: %s", pod_name, e)
                        logs[pod_name] = f"Error fetching logs: {e}"
                else:
                    # If the pod is in Pending status, no logs should be fetched
                    logs[pod_name] = "Pod is in Pending status, logs unavailable"

        except ApiException as e:
            logger.error("Kubernetes API exception when listing pods: %s", e)
            raise RuntimeError("Failed to fetch logs") from e

        return logs

    def get_task_info(self, task_id: str) -> dict:
        """
        Retrieve detailed information for a task, including logs, CPU, memory usage, and runtime.

        Args:
            task_id (str): The task ID to filter pods by.

        Returns:
            dict: A dictionary containing detailed task information including logs, status, memory,
            CPU usage, and runtime.
        """
        # Fetch task logs using the fetch_task_logs method
        logs = self.fetch_task_logs(task_id)

        # Get pod details using task_id as a label selector
        label_selector = f"stelar.task-id={task_id}"
        try:
            pods = self.v1.list_namespaced_pod(
                namespace=self.namespace, label_selector=label_selector
            )
        except ApiException as e:
            return {"error": f"An error occurred while fetching pod details: {str(e)}"}

        task_info = {}

        if not pods.items:
            # Handle the case where no pods are found
            task_info["message"] = "No logs available for the specified task execution"
            return task_info

        # Process the pods and fetch their details if pods exist
        for pod in pods.items:
            pod_name = pod.metadata.name

            # Fetch pod status and logs
            pod_status = pod.status.phase  # 'Succeeded', 'Failed', etc.
            container_status = (
                pod.status.container_statuses[0]
                if pod.status.container_statuses
                else None
            )

            if container_status:
                task_info[pod_name] = {
                    "status": pod_status,
                    "logs": logs.get(
                        pod_name, "Logs unavailable"
                    ),  # Using the logs fetched above
                }
            else:
                task_info[pod_name] = {
                    "status": "Unknown",
                    "logs": logs.get(pod_name, "Logs unavailable"),
                }

        # Return the task info as a dictionary
        return task_info

    def create_task(self, spec: JobSpec) -> tuple[str, str]:
        try:
            job_manifest = spec.manifest(self)
            job = self.batch.create_namespaced_job(
                body=job_manifest, namespace=self.namespace
            )
            logger.info("Created job from manifest: %s", job)
        except ApiException as e:
            logger.error("Kubernetes API exception: %a", e.args)
            raise RuntimeError("Failed to create task") from e

        job_id = job.metadata.uid
        job_name = job.metadata.name
        return job_id, job_name
