import pytest

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
