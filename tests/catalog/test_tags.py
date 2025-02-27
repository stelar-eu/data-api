# import pyjq
import pytest


# An auto-fixture that deletes the 'test_vocab1' vocabulary
# if it exists!
@pytest.fixture()
def clean_vocab1(DC):
    try:
        for tag in pyjq.all(".result.tags|.[]|.id", DC.vocabulary_show(id="vocab1")):
            DC.tag_delete(tag)
        DC.vocabulary_delete(id="vocab1")
    except Exception:
        pass


@pytest.fixture()
def vocab1(app_client, clean_vocab1):
    response = app_client.post(
        "/api/v2/vocabulary",
        json={
            "name": "vocab1",
            "tags": [{"name": n} for n in ["tag1", "tag2", "tag3"]],
        },
    )
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert result["name"] == "vocab1"
    assert len(result["tags"]) == 3
    assert {t["name"] for t in result["tags"]} == {"tag1", "tag2", "tag3"}

    yield result

    assert app_client.delete(f"/api/v2/vocabulary/{result['id']}").status_code == 200


def test_vocabulary_create(app_client, vocab1):
    assert vocab1["name"] == "vocab1"
    assert len(vocab1["tags"]) == 3
    assert {t["name"] for t in vocab1["tags"]} == {"tag1", "tag2", "tag3"}


def test_vocabulary_get(app_client, vocab1):
    response = app_client.get(f"/api/v2/vocabulary/{vocab1['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert result["name"] == "vocab1"
    assert len(result["tags"]) == 3
    assert {t["name"] for t in result["tags"]} == {"tag1", "tag2", "tag3"}


def test_vocabulary_add_tag(app_client, vocab1):
    new_tags = vocab1["tags"] + [{"name": "tag4"}]

    response = app_client.put(
        f"/api/v2/vocabulary/{vocab1['id']}",
        json={"tags": new_tags},
    )
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert result["name"] == "vocab1"
    assert len(result["tags"]) == 4
    assert {t["name"] for t in result["tags"]} == {"tag1", "tag2", "tag3", "tag4"}


def test_vocabulary_patch_failed(app_client, vocab1):
    response = app_client.patch(
        f"/api/v2/vocabulary/{vocab1['id']}",
        json={"name": "vocab2"},
    )
    assert response.status_code == 405
    assert not response.json["success"]


def test_vocabulary_tag_create(app_client, vocab1):
    response = app_client.post(
        "/api/v2/tag",
        json={
            "name": "tag_new",
            "vocabulary_id": vocab1["id"],
        },
    )
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert result["name"] == "tag_new"
    assert result["vocabulary_id"] == vocab1["id"]


def test_vocabulary_tag_get(app_client, vocab1):
    response = app_client.get(f"/api/v2/tag/{vocab1['tags'][0]['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert result["name"] == "tag1"
    assert result["vocabulary_id"] == vocab1["id"]


def test_vocabulary_tag_get_by_tagspec(app_client, vocab1):
    response = app_client.get(f"/api/v2/tag/{vocab1['name']}:tag3")
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert result["name"] == "tag3"
    assert result["vocabulary_id"] == vocab1["id"]


def test_vocabulary_tag_delete(app_client, vocab1):
    response = app_client.delete(f"/api/v2/tag/{vocab1['tags'][0]['id']}")
    assert response.status_code == 200
    assert response.json["success"]

    # Get the vocabulary again
    response = app_client.get(f"/api/v2/vocabulary/{vocab1['id']}")
    assert response.status_code == 200
    assert response.json["success"]
    result = response.json["result"]
    assert len(result["tags"]) == 2
    assert {t["name"] for t in result["tags"]} == {"tag2", "tag3"}
