import pytest
import execution.kubernetes as k
from execution.engine import ExecEngine

from kubernetes import client as klient


def test_factory(kconfig):
    "Test factory creation from minimal config"

    factory = k.configure({
        'API_URL': 'http://localhost/',
        'execution': {
            "engine": "kubernetes",
            "namespace": "playground",
            "config": 'kubectl'
        },
    }, client_config=False)

    engine = factory()

    assert isinstance(engine, ExecEngine)
    assert isinstance(engine, k.K8sExecEngine)
    assert engine.api_url == 'http://localhost/'
    assert engine.namespace == 'playground'

#
# Link to Alex's  
#
# https://github.com/alexZeakis/pyTokenJoin/tree/main/docker
##
#


def kube_get_job(namespace, task_id):
    batch = klient.BatchV1Api()
    return batch.read_namespaced_job(name=f"stelar-task-{task_id}", namespace=namespace)


def test_kubernetes_create_task(testcluster_kubernetes):

    # Create a sample task in the default kubernetes cluster
    factory = k.configure(testcluster_kubernetes)
    engine = factory()

    tool_name = "vsam/testservice"
    token = "abracadabra"

    import uuid
    task_id = str(uuid.uuid4())

    # Create the job
    job_uid = engine.create_task(tool_name, token, task_id)

    # try to read the job by name
    job_obj = kube_get_job(engine.namespace, task_id)

    assert job_obj.metadata.uid == job_uid

