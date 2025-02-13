from datetime import datetime, timedelta

import pyjq
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
    except:
        pass

    with mdb_conn:
        with mdb_conn.cursor() as cur:
            cur.execute(
                "DELETE FROM klms.workflow_execution WHERE workflow_uuid = %s", (pid,)
            )


def test_process_creation(app_context, DC, mdb_conn):
    stelar_klms = ORGANIZATION.get_entity("stelar-klms")
    assert stelar_klms is not None
    assert stelar_klms["name"] == "stelar-klms"
    assert stelar_klms["type"] == "organization"
    assert stelar_klms["name"] == "stelar-klms"

    johndoe = get_user("johndoe")

    proc = PROCESS.create_process(
        johndoe, organization="stelar-klms", title="Test Process Description"
    )
    assert proc is not None
    print(proc)
    assert proc["title"] == "Test Process Description"
    assert proc["owner_org"] == stelar_klms["id"]
    assert isinstance(proc["metadata_created"], datetime)
    assert isinstance(proc["start_date"], datetime)
    assert isinstance(proc["end_date"], datetime | None)

    proc2 = PROCESS.get_entity(proc["id"])
    proc3 = PROCESS.get_entity(proc2["name"])
    assert proc2 == proc3
    assert proc2["title"] == "Test Process Description"
    assert proc2["owner_org"] == stelar_klms["id"]
    assert proc2["name"] == proc["name"]
    assert proc2["id"] == proc["id"]
    assert isinstance(proc2["metadata_created"], datetime)
    assert isinstance(proc2["start_date"], datetime)
    assert isinstance(proc2["end_date"], datetime | None)

    purge_process(proc["id"], DC, mdb_conn)


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


def test_process_api_create(app_client, DC, mdb_conn):
    # Create a new process
    response = app_client.post(
        "/api/v2/process",
        json={
            "owner_org": "stelar-klms",
            "title": "Test Process Description",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["title"] == "Test Process Description"

    # clean everything up...
    purge_process(data["result"]["id"], DC, mdb_conn)


def test_process_api_create_failed(app_client, DC, mdb_conn):
    # Create a new process with missing owner_org
    response = app_client.post(
        "/api/v2/process",
        json={
            "title": "Test Process Description",
        },
    )
    assert response.status_code == 422
    data = response.get_json()
    assert data["success"] is False
    assert "owner_org" in pyjq.all("..|objects|keys_unsorted[]", data)


def test_process_api_create_minimal(app_client, DC, mdb_conn):
    # Create a new process with missing title
    response = app_client.post(
        "/api/v2/process",
        json={
            "owner_org": "stelar-klms",
        },
    )
    assert response.status_code == 200
    try:
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["name"].startswith("workflow-process-")
        assert data["result"]["workflow"] is None
        assert data["result"]["exec_state"] == "running"
        assert data["result"]["state"] == "active"

        assert isinstance(data["result"]["metadata_created"], str)
        assert datetime.fromisoformat(data["result"]["metadata_created"])
        assert isinstance(data["result"]["start_date"], str)
        assert (sdd := datetime.fromisoformat(data["result"]["start_date"]))
        assert datetime.now() - sdd < timedelta(seconds=1)

    finally:
        purge_process(data["result"]["id"], DC, mdb_conn)


def test_process_update_metadata(app_client, DC, mdb_conn):
    # Create a new process
    response = app_client.post(
        "/api/v2/process",
        json={
            "owner_org": "stelar-klms",
            "title": "Test Process Description",
            "version": "1.0.0",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["title"] == "Test Process Description"
    assert data["result"]["version"] == "1.0.0"

    # Update the process
    response = app_client.patch(
        f"/api/v2/process/{data['result']['id']}",
        json={
            "title": "New Test Process Description",
            "version": "1.1.0",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["title"] == "New Test Process Description"
    assert data["result"]["version"] == "1.1.0"

    # Get the object and check the changes
    response = app_client.get(f"/api/v2/process/{data['result']['id']}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["title"] == "New Test Process Description"
    assert data["result"]["version"] == "1.1.0"

    # clean everything up...
    purge_process(data["result"]["id"], DC, mdb_conn)


@pytest.fixture
def aprocess(app_client, DC, mdb_conn):
    # Create a new process
    response = app_client.post(
        "/api/v2/process",
        json={
            "owner_org": "stelar-klms",
            "title": "Test Process Description",
            "version": "1.0.0",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["title"] == "Test Process Description"
    assert data["result"]["version"] == "1.0.0"

    yield data["result"]

    # clean everything up...
    purge_process(data["result"]["id"], DC, mdb_conn)


def test_process_succeeded(app_client, aprocess):
    assert aprocess["exec_state"] == "running"

    # Complete the process
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "exec_state": "succeeded",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    proc = data["result"]
    assert proc["exec_state"] == "succeeded"
    assert proc["end_date"] is not None
    assert isinstance(proc["end_date"], str)
    assert abs(datetime.fromisoformat(proc["end_date"]) - datetime.now()) < timedelta(
        seconds=2
    )

    # Try to make it failed
    response = app_client.patch(
        f"/api/v2/process/{proc['id']}",
        json={
            "exec_state": "failed",
        },
    )

    assert response.status_code == 409
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"

    # Try to make it running
    response = app_client.patch(
        f"/api/v2/process/{proc['id']}",
        json={
            "exec_state": "running",
        },
    )

    assert response.status_code == 409
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"


def test_process_failed(app_client, aprocess):
    assert aprocess["exec_state"] == "running"

    # Complete the process
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "exec_state": "failed",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    proc = data["result"]
    assert proc["exec_state"] == "failed"
    assert proc["end_date"] is not None
    assert isinstance(proc["end_date"], str)
    assert abs(datetime.fromisoformat(proc["end_date"]) - datetime.now()) < timedelta(
        seconds=2
    )

    # Try to make it succeeded
    response = app_client.patch(
        f"/api/v2/process/{proc['id']}",
        json={
            "exec_state": "succeeded",
        },
    )

    assert response.status_code == 409
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"

    # Try to make it running
    response = app_client.patch(
        f"/api/v2/process/{proc['id']}",
        json={
            "exec_state": "running",
        },
    )

    assert response.status_code == 409
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"


def test_process_delete(app_client, aprocess):
    # Delete the process while running
    response = app_client.delete(f"/api/v2/process/{aprocess['id']}")
    assert response.status_code == 409
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["__type"] == "ConflictError"

    # Mark it as succeeded
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "exec_state": "succeeded",
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True

    # Now delete it
    response = app_client.delete(f"/api/v2/process/{aprocess['id']}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True

    # Try to purge it
    response = app_client.delete(f"/api/v2/process/{aprocess['id']}?purge=true")
    assert response.status_code == 405
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["__type"] == "NotAllowedError"

    # Try to get it
    response = app_client.get(f"/api/v2/process/{aprocess['id']}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["state"] == "deleted"


def test_process_set_tags(app_client, aprocess):
    # Set tags
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "tags": ["tag1", "tag2", "tag3"],
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["tags"] == ["tag1", "tag2", "tag3"]

    # Add tags
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "tags": ["tag4", "tag5"],
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["tags"] == ["tag4", "tag5"]

    # Remove tags
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "tags": ["tag2", "tag4"],
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["tags"] == ["tag2", "tag4"]

    # Remove all tags
    response = app_client.patch(
        f"/api/v2/process/{aprocess['id']}",
        json={
            "tags": [],
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["tags"] == []
