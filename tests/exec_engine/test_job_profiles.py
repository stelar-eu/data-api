import pytest
from apiflask.validators import ValidationError

from execution.job import JobProfileSchema, JobSpec


def test_jp_schema():
    schema = JobProfileSchema()

    v = {
        "image": "test/image:latest",
        "description": "A test job",
        "image_pull_policy": "Always",
        "image_pull_secrets": ["test-secret"],
        "cpu_request": "0.5",
        "cpu_limit": "1000m",
        "memory_request": "512Mi",
        "memory_limit": "1Gi",
        "backoff_limit": 3,
        "restart_policy": "OnFailure",
        "ttl_seconds_after_finished": 3600,
    }

    s = schema.load(v)
    assert s["image"] == "test/image:latest"
    assert s["description"] == "A test job"
    assert s["image_pull_policy"] == "Always"
    assert s["image_pull_secrets"] == ["test-secret"]
    assert s["cpu_request"] == "0.5"
    assert s["cpu_limit"] == "1000m"
    assert s["memory_request"] == "512Mi"
    assert s["memory_limit"] == "1Gi"
    assert s["ttl_seconds_after_finished"] == 3600

    d = schema.dump(s)
    assert d == v


@pytest.mark.parametrize(
    "bad_spec",
    [
        {
            "image": "test/image:latest",
            "description": "A test job",
            "image_pull_policy": "InvalidPolicy",
        },
        {
            "image": "test/image:latest",
            "description": "A test job",
            "image_pull_policy": "Always",
            "cpu_request": "a lot",
        },
        {
            "ttl_seconds_after_finished": "not a number",
        },
        {
            "memory": 1000000,  # A number instead of a string
        },
        {
            "backoff_limit": -1,  # Invalid negative value
        },
        {
            "restart_policy": "InvalidPolicy",  # Invalid restart policy
        },
        {
            "image_pull_secrets": [
                "valid-secret",
                "",
                "another-secret",
            ],  # Empty string in list
        },
        {
            "image_pull_secrets": ["valid-secret", 11],
        },
    ],
)
def test_bad_jp_load_fails(bad_spec):
    schema = JobProfileSchema()
    with pytest.raises(ValidationError):
        schema.load(bad_spec)


def test_job_profile_creation():
    tool = "Test Tool"
    image = "test/image:latest"
    spec = {
        "name": "Test Job",
        "description": "A job for testing",
    }

    job_profile = JobSpec(
        tool,
        image,
        spec,
        {
            "task_id": "123",
            "token": "abc",
            "signature": "xyz",
            "creator": "user1",
            "process_id": "proc1",
        },
    )

    assert job_profile.tool_name == tool
    assert job_profile.image == image
    assert job_profile.profile == spec
    assert job_profile.task_info["task_id"] == "123"
    assert job_profile.task_info["token"] == "abc"
    assert job_profile.task_info["signature"] == "xyz"
    assert job_profile.task_info["creator"] == "user1"
    assert job_profile.task_info["process_id"] == "proc1"
    # assert job_profile.name == "Test Job"
    # assert job_profile.description == "A job for testing"
