from datetime import datetime, timedelta, timezone

import jmespath
import pytest
from marshmallow import ValidationError

from cutils import ORGANIZATION
from kutils import get_user
from wxutils import PROCESS, WorkflowProcessSchema

#  The followng fixes a bug in FlaskClient !!
# werkzeug.__version__ = "3.1.3"


def purge_process(pid, DC, mdb_conn):
    # Purge the process by deleting both the
    # package and the db entry.

    # Delete the package
    try:
        DC.dataset_purge(id=pid)
    except Exception:
        pass

    with mdb_conn:
        with mdb_conn.cursor() as cur:
            cur.execute(
                "DELETE FROM klms.workflow_execution WHERE workflow_uuid = %s", (pid,)
            )


def test_process_schema_create(DC):
    s = WorkflowProcessSchema()

    # "grarbage" attribute causes a validation error
    with pytest.raises(ValidationError):
        s.load(
            {  # "name": "thename",
                "owner_org": "theowner",
                "title": "thetitle",
                "grabage": "garbage",
            }
        )

    # Missing "owner_org" (required) !!
    with pytest.raises(ValidationError):
        s.load({"title": "thetitle"})


def test_process_schema_update(DC):
    s = WorkflowProcessSchema(partial=True)

    # "grarbage" attribute causes a validation error
    with pytest.raises(ValidationError):
        s.load(
            {  # "name": "thename",
                "owner_org": "theowner",
                "title": "thetitle",
                "grabage": "garbage",
            }
        )

    # Missing "owner_org" no problem !!
    assert s.load({"title": "thetitle"}) == {"title": "thetitle"}
    assert s.load({"name": "thename"}) == {"name": "thename"}


def test_process_api_create(testcli, DC, mdb_conn):
    # Create a new process
    response = testcli.POST(
        "v2/process",
        owner_org="stelar-klms",
        title="Test Process Description",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["title"] == "Test Process Description"

    # clean everything up...
    purge_process(data["result"]["id"], DC, mdb_conn)


def test_process_api_create_failed(testcli):
    # Create a new process with missing owner_org
    response = testcli.POST("v2/process", title="Test Process Description")
    assert response.status_code == 422
    data = response.json()
    assert data["success"] is False
    assert "owner_org" in jmespath.search("error.detail.json", data)


def test_process_api_create_minimal(testcli, DC, mdb_conn):
    # Create a new process with missing title
    response = testcli.POST(
        "v2/process",
        owner_org="stelar-klms",
    )
    assert response.status_code == 200
    try:
        data = response.json()
        assert data["success"] is True
        assert data["result"]["name"].startswith("workflow-process-")
        assert data["result"]["workflow"] is None
        assert data["result"]["exec_state"] == "running"
        assert data["result"]["state"] == "active"

        assert isinstance(data["result"]["metadata_created"], str)
        assert datetime.fromisoformat(data["result"]["metadata_created"])
        assert isinstance(data["result"]["start_date"], str)
        assert (sdd := datetime.fromisoformat(data["result"]["start_date"]))
        assert datetime.utcnow() - sdd < timedelta(seconds=3)

    finally:
        purge_process(data["result"]["id"], DC, mdb_conn)


def test_process_update_metadata(testcli, DC, mdb_conn):
    # Create a new process
    response = testcli.POST(
        "v2/process",
        owner_org="stelar-klms",
        title="Test Process Description",
        version="1.0.0",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["title"] == "Test Process Description"
    assert data["result"]["version"] == "1.0.0"

    # Update the process
    response = testcli.PATCH(
        f"v2/process/{data['result']['id']}",
        title="New Test Process Description",
        version="1.1.0",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["title"] == "New Test Process Description"
    assert data["result"]["version"] == "1.1.0"

    # Get the object and check the changes
    response = testcli.GET(f"v2/process/{data['result']['id']}")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["title"] == "New Test Process Description"
    assert data["result"]["version"] == "1.1.0"

    # clean everything up...
    purge_process(data["result"]["id"], DC, mdb_conn)


@pytest.fixture
def aprocess(testcli, DC, mdb_conn):
    # Create a new process
    response = testcli.POST(
        "v2/process",
        owner_org="stelar-klms",
        title="Test Process Description",
        version="1.0.0",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["title"] == "Test Process Description"
    assert data["result"]["version"] == "1.0.0"

    yield data["result"]

    # clean everything up...
    purge_process(data["result"]["id"], DC, mdb_conn)


def test_process_succeeded(testcli, aprocess):
    assert aprocess["exec_state"] == "running"

    # Complete the process
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}",
        exec_state="succeeded",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    proc = data["result"]
    assert proc["exec_state"] == "succeeded"
    assert proc["end_date"] is not None
    assert isinstance(proc["end_date"], str)
    assert abs(
        datetime.fromisoformat(proc["end_date"]) - datetime.utcnow()
    ) < timedelta(seconds=2)

    # Try to make it failed
    response = testcli.PATCH(
        f"v2/process/{proc['id']}",
        exec_state="failed",
    )

    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"

    # Try to make it running
    response = testcli.PATCH(
        f"v2/process/{proc['id']}",
        exec_state="running",
    )

    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"


def test_process_failed(testcli, aprocess):
    assert aprocess["exec_state"] == "running"

    # Complete the process
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}",
        exec_state="failed",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    proc = data["result"]
    assert proc["exec_state"] == "failed"
    assert proc["end_date"] is not None
    assert isinstance(proc["end_date"], str)
    assert abs(
        datetime.fromisoformat(proc["end_date"]) - datetime.utcnow()
    ) < timedelta(seconds=2)

    # Try to make it succeeded
    response = testcli.PATCH(f"v2/process/{proc['id']}", exec_state="succeeded")

    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"

    # Try to make it running
    response = testcli.PATCH(f"v2/process/{proc['id']}", exec_state="running")

    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"


def test_process_delete(testcli, aprocess):
    # Delete the process while running
    response = testcli.DELETE(f"v2/process/{aprocess['id']}")
    assert response.status_code == 409
    data = response.json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"

    # Mark it as succeeded
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}",
        exec_state="succeeded",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

    # Now delete it
    response = testcli.DELETE(f"v2/process/{aprocess['id']}")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

    # Try to purge it
    response = testcli.DELETE(f"v2/process/{aprocess['id']}?purge=true")
    assert response.status_code == 405
    data = response.json()
    assert data["success"] is False
    assert data["error"]["__type"] == "NotAllowedError"

    # Try to get it
    response = testcli.GET(f"v2/process/{aprocess['id']}")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["state"] == "deleted"


def test_process_set_tags(testcli, aprocess):
    # Set tags
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}", tags=["tag1", "tag2", "tag3"]
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["tags"] == ["tag1", "tag2", "tag3"]

    # Add tags
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}",
        tags=["tag4", "tag5"],
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["tags"] == ["tag4", "tag5"]

    # Remove tags
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}",
        tags=["tag2", "tag4"],
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["tags"] == ["tag2", "tag4"]

    # Remove all tags
    response = testcli.PATCH(
        f"v2/process/{aprocess['id']}",
        tags=[],
    )

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["tags"] == []
