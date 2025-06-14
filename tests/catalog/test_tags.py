import jmespath
import pytest


# An auto-fixture that deletes the 'test_vocab1' vocabulary
# if it exists!
@pytest.fixture()
def clean_vocab1(DC):
    try:
        voc = DC.vocabulary_show(name="vocab1")
        for tag in jmespath.search("result.tags[].id", voc):
            DC.tag_delete(tag)
        DC.vocabulary_delete(id="vocab1")
    except Exception:
        pass


@pytest.fixture()
def vocab1(testcli, clean_vocab1):
    response = testcli.POST(
        "v2/vocabulary",
        name="vocab1",
        tags=[{"name": n} for n in ["tag1", "tag2", "tag3"]],
    )
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert result["name"] == "vocab1"
    assert len(result["tags"]) == 3
    assert {t["name"] for t in result["tags"]} == {"tag1", "tag2", "tag3"}

    yield result

    assert testcli.DELETE(f"v2/vocabulary/{result['id']}").status_code == 200


def test_vocabulary_create(testcli, vocab1):
    assert vocab1["name"] == "vocab1"
    assert len(vocab1["tags"]) == 3
    assert {t["name"] for t in vocab1["tags"]} == {"tag1", "tag2", "tag3"}


def test_vocabulary_get(testcli, vocab1):
    response = testcli.GET(f"v2/vocabulary/{vocab1['id']}")
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert result["name"] == "vocab1"
    assert len(result["tags"]) == 3
    assert {t["name"] for t in result["tags"]} == {"tag1", "tag2", "tag3"}


def test_vocabulary_add_tag(testcli, vocab1):
    new_tags = vocab1["tags"] + [{"name": "tag4"}]

    response = testcli.PUT(f"v2/vocabulary/{vocab1['id']}", tags=new_tags)
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert result["name"] == "vocab1"
    assert len(result["tags"]) == 4
    assert {t["name"] for t in result["tags"]} == {"tag1", "tag2", "tag3", "tag4"}


def test_vocabulary_patch_failed(testcli, vocab1):
    response = testcli.PATCH(
        f"v2/vocabulary/{vocab1['id']}",
        json={"name": "vocab2"},
    )
    assert response.status_code == 405
    assert not response.json()["success"]


def test_vocabulary_tag_create(testcli, vocab1):
    response = testcli.POST("v2/tag", name="tag_new", vocabulary_id=vocab1["id"])
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert result["name"] == "tag_new"
    assert result["vocabulary_id"] == vocab1["id"]


def test_vocabulary_tag_get(testcli, vocab1):
    response = testcli.GET(f"v2/tag/{vocab1['tags'][0]['id']}")
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert result["name"] == "tag1"
    assert result["vocabulary_id"] == vocab1["id"]


def test_vocabulary_tag_get_by_tagspec(testcli, vocab1):
    response = testcli.GET(f"v2/tag/{vocab1['name']}:tag3")
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert result["name"] == "tag3"
    assert result["vocabulary_id"] == vocab1["id"]


def test_vocabulary_tag_delete(testcli, vocab1):
    response = testcli.DELETE(f"v2/tag/{vocab1['tags'][0]['id']}")
    assert response.status_code == 200
    assert response.json()["success"]

    # Get the vocabulary again
    response = testcli.GET(f"v2/vocabulary/{vocab1['id']}")
    assert response.status_code == 200
    assert response.json()["success"]
    result = response.json()["result"]
    assert len(result["tags"]) == 2
    assert {t["name"] for t in result["tags"]} == {"tag2", "tag3"}
