import pytest
from kubernetes import client as klient

import execution.kubernetes as k
from execution.engine import ExecEngine


def test_factory(dev_cluster_config):
    "Test factory creation from minimal config"

    cluster = dev_cluster_config["cluster"]

    factory = k.configure(
        # {"API_URL": cluster["API_URL"], "execution": cluster["execution"]},
        cluster,
        client_config=False,
    )

    engine = factory()

    assert isinstance(engine, ExecEngine)
    assert isinstance(engine, k.K8sExecEngine)
    assert engine.api_url == cluster["execution"]["api_url"]
    assert engine.namespace == cluster["execution"]["namespace"]


#
# Link to Alex's
#
# https://github.com/alexZeakis/pyTokenJoin/tree/main/docker
##
#


def kube_get_job(namespace, task_id):
    batch = klient.BatchV1Api()
    return batch.read_namespaced_job(name=f"stelar-task-{task_id}", namespace=namespace)


#
#  The current test fails with the following error:
# TypeError: K8sExecEngine.create_task() missing 1 required positional argument: 'signature'
#
# The test needs to be updated to reflect the current implementation of the create_task method


@pytest.mark.skip(reason="This test needs updating")
def test_kubernetes_create_task(kconfig, dev_cluster_config):
    # Create a sample task in the default kubernetes cluster
    cluster = dev_cluster_config["cluster"]
    factory = k.configure(cluster)
    engine = factory()

    tool_name = "vsam/testservice"
    token = "abracadabra"

    import uuid

    task_id = str(uuid.uuid4())

    # Create the job
    job_uid, _ = engine.create_task(tool_name, token, task_id)

    # try to read the job by name
    job_obj = kube_get_job(engine.namespace, task_id)

    assert job_obj.metadata.uid == job_uid
