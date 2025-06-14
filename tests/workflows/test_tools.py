import pytest

pytestmark = pytest.mark.skip()

tool_create = {
    # "title": "MapReduce Word Count",
    "name": "word-count",
    "owner_org": "stelar-klms",
    "notes": "Word Count using MapReduce",
    "programming_language": "Python",
    "git_repository": "https://github.com/stelar-eu/data-api.git",
}


@pytest.fixture
def new_tool(app_client, DC):
    response = app_client.post("/api/v2/tool", json=tool_create)
    assert response.status_code == 200
    assert response.json["success"]

    yield response.json["result"]

    eid = response.json["result"]["id"]
    assert DC.dataset_purge(id=eid)["success"]


def test_create_tool(new_tool):
    assert new_tool["type"] == "tool"
    assert new_tool["name"] == "word-count"
    assert new_tool["notes"] == "Word Count using MapReduce"
    assert new_tool["programming_language"] == "Python"
    assert new_tool["git_repository"] == "https://github.com/stelar-eu/data-api.git"


def test_create_tool_errors(app_client):
    assert app_client.post("/api/v2/tool", json={}).status_code == 422
    assert (
        app_client.post("/api/v2/tool", json=dict(name="!bad_name")).status_code == 422
    )
    assert (
        app_client.post("/api/v2/tool", json=dict(owner_org="stelar-klms")).status_code
        == 422
    )
    assert (
        app_client.post(
            "/api/v2/tool",
            json=dict(name="good-tool", owner_org="stelar-klms", url="weird"),
        ).status_code
        == 422
    )


def test_update_tool(app_client, new_tool):
    response = app_client.put(
        f"/api/v2/tool/{new_tool['id']}", json={"notes": "New Note"}
    )
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["notes"] == "New Note"

    response = app_client.get(f"/api/v2/tool/{new_tool['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["notes"] == "New Note"


def test_update_tool_programming_language(app_client, new_tool):
    response = app_client.put(
        f"/api/v2/tool/{new_tool['id']}", json={"programming_language": "Java"}
    )
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["programming_language"] == "Java"

    response = app_client.get(f"/api/v2/tool/{new_tool['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["programming_language"] == "Java"


def test_update_tool_extra1(app_client, new_tool):
    response = app_client.put(
        f"/api/v2/tool/{new_tool['id']}", json={"extras": {"key": "value"}}
    )
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["extras"] == {"key": "value"}

    response = app_client.get(f"/api/v2/tool/{new_tool['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["extras"] == {"key": "value"}


def test_update_tool_extra2(app_client, new_tool):
    response = app_client.put(
        f"/api/v2/tool/{new_tool['id']}",
        json={"extras": {"key": "value"}, "programming_language": "Java"},
    )
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["extras"] == {"key": "value"}
    assert response.json["result"]["programming_language"] == "Java"

    response = app_client.get(f"/api/v2/tool/{new_tool['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["extras"] == {"key": "value"}
    assert response.json["result"]["programming_language"] == "Java"

    # Update back into Python
    response = app_client.put(
        f"/api/v2/tool/{new_tool['id']}", json={"programming_language": "Python"}
    )
    assert response.status_code == 200
    assert response.json["success"]
    assert (
        response.json["result"]["programming_language"] == "Python"
    )  # Check that it is Python

    response = app_client.get(f"/api/v2/tool/{new_tool['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    assert (
        response.json["result"]["programming_language"] == "Python"
    )  # Check that it is Python

    # Now update the extra to be empty
    response = app_client.put(f"/api/v2/tool/{new_tool['id']}", json={"extras": {}})
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["extras"] == {}  # Check that it is empty
    assert (
        response.json["result"]["programming_language"] == "Python"
    )  # Check that it is Python

    response = app_client.get(f"/api/v2/tool/{new_tool['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    assert response.json["result"]["extras"] == {}  # Check that it is empty
    assert (
        response.json["result"]["programming_language"] == "Python"
    )  # Check that it is Python
