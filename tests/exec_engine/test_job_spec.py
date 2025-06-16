from __future__ import annotations

from execution.job import JobSpec
from execution.kubernetes import K8sExecEngine


def test_job_spec_creation():
    tool = "test-tool"
    image = "latest"

    profile = {
        "name": "Test Job",
        "description": "A job for testing",
    }
    task_info = {
        "task_id": "123",
        "token": "abc",
        "signature": "xyz",
        "creator": "user1",
        "process_id": "proc1",
    }

    jobspec = JobSpec(tool, image, profile, task_info)

    assert jobspec.tool_name == tool
    assert jobspec.image == image
    assert jobspec.profile == profile
    assert jobspec.task_info == task_info


def test_job_spec_manifest():
    task_info = {
        "id": "12345",
        "tool_name": "test_tool",
        "signature": "544635735424572034572034572034572034",
        "token": "test_token",
        "creator": "test_creator",
        "process_id": "test_process",
    }

    profile = {
        "image_pull_policy": "Never",
        "image_pull_secrets": ["my-secret"],
        "backoff_limit": 2,
        "cpu_request": "2500m",
        "memory_request": "4Gi",
    }

    default_profile = {
        "image_pull_policy": "IfNotPresent",
        "image_pull_secrets": ["default-secret"],
        "backoff_limit": 3,
        "cpu_request": "1000m",
        "memory_request": "2Gi",
        "ttl_seconds_after_finished": 86400,  # 1 day in seconds
    }

    # Create a sample job specification
    job_spec = JobSpec(
        tool_name="test_tool",
        image="test_tool:0.3.2",
        profile=profile,
        task_info=task_info,
    )

    engine = K8sExecEngine(
        api_url="http://stelarapi/",
        namespace="stelar-test",
        registry_address="img.stelar.com",
        registry_org="stelar",
        default_profile=default_profile,
    )

    m = job_spec.manifest(engine)

    assert m.metadata.name == "task-12345-test-tool"
    assert m.spec.template.metadata.labels["stelar.tool-name"] == "test_tool"
    assert (
        m.spec.template.spec.containers[0].image
        == "img.stelar.com/stelar/test_tool:0.3.2"
    )
    assert m.spec.template.spec.restart_policy is None
    assert m.spec.backoff_limit == 2
    assert m.spec.ttl_seconds_after_finished == 86400  # 1 day in seconds
    assert set(x.name for x in m.spec.template.spec.image_pull_secrets) == {
        "my-secret",
        "default-secret",
    }
    assert m.spec.template.spec.containers[0].image_pull_policy == "Never"
    assert m.spec.template.spec.containers[0].resources.requests["cpu"] == "2500m"
    assert m.spec.template.spec.containers[0].resources.requests["memory"] == "4Gi"
    assert m.spec.template.spec.containers[0].resources.limits is None

    assert m.metadata.labels["stelar.metadata.class"] == "task-execution"
    assert m.metadata.labels["stelar.task-id"] == "12345"
    assert m.metadata.labels["stelar.tool-name"] == "test_tool"
    assert m.metadata.labels["stelar.creator"] == "test_creator"
    assert m.metadata.labels["stelar.process-id"] == "test_process"


def test_job_spec_manifest():
    task_info = {
        "id": "12345",
        "tool_name": "test_tool",
        "signature": "544635735424572034572034572034572034",
        "token": "test_token",
        "creator": "test_creator",
        "process_id": "test_process",
    }

    profile = {
        "image_pull_policy": "IfNotPresent",
        "image_pull_secrets": ["my-secret"],
        "backoff_limit": 2,
        "cpu_request": "2500m",
        "memory_request": "4Gi",
    }

    default_profile = {
        "image_pull_policy": "Always",
        "image_pull_secrets": ["default-secret"],
        "backoff_limit": 3,
        "cpu_request": "1000m",
        "memory_request": "2Gi",
        "ttl_seconds_after_finished": 86400,  # 1 day in seconds
    }

    # Create a sample job specification
    job_spec = JobSpec(
        tool_name="test_tool",
        image="test_tool:0.3.2",
        profile=profile,
        task_info=task_info,
    )

    engine = K8sExecEngine(
        api_url="http://stelarapi/",
        namespace="stelar-test",
        registry_address="img.stelar.com",
        registry_org="stelar",
        default_profile=default_profile,
    )

    m = job_spec.manifest(engine)

    # Metadata

    assert m.metadata.name == "task-12345-test-tool"
    assert m.metadata.labels["stelar.metadata.class"] == "task-execution"
    assert m.metadata.labels["stelar.task-id"] == "12345"
    assert m.metadata.labels["stelar.tool-name"] == "test_tool"
    assert m.metadata.labels["stelar.creator"] == "test_creator"
    assert m.metadata.labels["stelar.process-id"] == "test_process"

    # Spec

    assert m.spec.template.spec.restart_policy is None
    assert m.spec.backoff_limit == 2
    assert m.spec.ttl_seconds_after_finished == 86400  # 1 day in seconds
    assert set(x.name for x in m.spec.template.spec.image_pull_secrets) == {
        "my-secret",
        "default-secret",
    }

    # template
    assert m.spec.template.metadata.labels["stelar.tool-name"] == "test_tool"

    # Container
    assert (
        m.spec.template.spec.containers[0].image
        == "img.stelar.com/stelar/test_tool:0.3.2"
    )
    assert m.spec.template.spec.containers[0].image_pull_policy == "IfNotPresent"
    assert m.spec.template.spec.containers[0].resources.requests["cpu"] == "2500m"
    assert m.spec.template.spec.containers[0].resources.requests["memory"] == "4Gi"
    assert m.spec.template.spec.containers[0].resources.limits is None
