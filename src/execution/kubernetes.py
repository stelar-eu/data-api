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
from typing import TYPE_CHECKING
import os
import logging
from .engine import ExecEngine
import kubernetes as k8s
from kubernetes.client.rest import ApiException


if TYPE_CHECKING:
    from .engine import ExecEngineFactory


# Default logger for this module
logger = logging.getLogger("exec")


def kubernetes_client_config(engine_config):
    """Configure kubernetes client.

    Args:
        engine_config (_type_): _description_
    """
    config = engine_config.get('config', 'incluster')

    match config:
        case 'incluster':
            logger.info("Loading kubernetes incluster config.")
            k8s.config.load_incluster_config()
        case 'kubeconfig':
            logger.info("Loading kubernetes from kube config.")
            k8s.config.load_kube_config()

        case _:
            raise ValueError(f"Kubernetes client config not understood: {config}")


def configure(cfg: dict, client_config=True) -> ExecEngineFactory:
    """Configure a docker execution engine factory

    Args:
        cfg (dict): Deployment configuration
        client_config (bool, optional): If true, configure the kubernetes client also. 
                        Defaults to True.
    Returns:
        ExecEngineFactory: Docker ExecEngine factory
    """

    # Initialize k8s configuration
    engine_config = cfg['execution']
    if engine_config['engine'] != 'kubernetes':
        raise ValueError("Execution engine is not 'kubernetes'")

    if client_config:
        kubernetes_client_config(engine_config)

    # Get execution namespace from engine config. If
    # misssing, use the 'API_NAMESPACE' environment var.
    # Else, raise an exception.
    nspace = engine_config.get('namespace', None)
    if nspace is None:
        nspace = os.environ.get('API_NAMESPACE', None)
    if nspace is None:
        raise RuntimeError("Execution namespace undefined")
    logger.info("Established namespace %s for task execution", nspace)

    # Define the factory function in here
    def factory() -> ExecEngine:
        # The api_url is available in cfg
        logger.info("Createed kubernetes task execution engine.")
        return K8sExecEngine(api_url=cfg['API_URL'], namespace=nspace)

    logger.info("Created kubernetes exec engine factory")
    return factory


class K8sExecEngine(ExecEngine):
    """This is a very simple implementation of a docker execution engine.

    A single instance of this class is also a docker factory.

    Args:
        ExecEngine (_type_): _description_
    """

    def __init__(self, api_url, namespace):
        self.api_url = api_url
        self.namespace = namespace
        self.v1 = k8s.client.CoreV1Api()
        self.batch = k8s.client.BatchV1Api()

    def _create_job_manifest(self, tool_name: str, token: str, task_id: str):
        # Create the resource for given tool
        from kubernetes.client import V1Container, V1PodSpec, V1ObjectMeta, V1JobSpec, V1Job
        from kubernetes.client import V1PodTemplateSpec

        jm = V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=V1ObjectMeta(
                name=f"stelar-task-{task_id}",
                labels={
                    "stelar.metadata.class": "task-execution",
                    "stelar.task-id": task_id,
                }
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
                        }
                    ),
                    spec=V1PodSpec(
                        containers=[
                            V1Container(
                                name="main",
                                image=tool_name,
                                image_pull_policy='Always',
                                args=[token, self.api_url, task_id]
                                ),
                        ],
                        restart_policy="Never"
                    )
                ),
                backoff_limit=4,
                ttl_seconds_after_finished=30,
            )
        )

        logger.info("Job manifest for task %s tool_name %s", task_id, tool_name)
        logger.debug("Job: %s", jm)
        return jm

    def create_task(self, tool_name: str, token: str, task_id: str) -> str:
        try:
            job_manifest = self._create_job_manifest(tool_name, token, task_id)
            print(job_manifest)
            job = self.batch.create_namespaced_job(body=job_manifest, namespace=self.namespace)
            logger.info("Created job from manifest: %s", job)
        except ApiException as e:
            logger.error("Kubernetes API exception: %a", e.args)
            raise RuntimeError("Failed to create task") from e
        job_id = job.metadata.uid
        return job_id
