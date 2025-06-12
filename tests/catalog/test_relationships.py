import pytest
from datafix import DataFix

from package import create_relationship, delete_relationship, get_relationships

pytestmark = pytest.mark.skip()


@pytest.fixture(scope="function", autouse=True)
def sample_packages_and_relationships(app):
    """Generate sample packages and relationships."""

    dfix = DataFix()

    packages = [
        {"name": "dataset1", "owner_org": "stelar-klms"},
        {"name": "dataset2", "owner_org": "stelar-klms"},
        {"name": "dataset3", "owner_org": "stelar-klms"},
        {"name": "dataset4", "owner_org": "stelar-klms"},
    ]
    for pkg in packages:
        dfix.dataset(**pkg)

    relationships = [
        ("dataset1", "dataset2", "parent_of"),
        ("dataset2", "dataset3", "child_of"),
        ("dataset3", "dataset4", "depends_on"),
    ]
    for i, (sub, obj, rel) in enumerate(relationships):
        dfix.relationship(sub, obj, rel, comment=f"comment {i}")

    with app.app_context():
        dfix.create()

    yield dfix

    with app.app_context():
        dfix.destroy()


def test_get_relationships_by_s(app_context):
    r = get_relationships("dataset2", None, None)
    assert len(r) == 2
    r.sort(key=lambda x: x["object_name"])
    assert r[0]["object_name"] == "dataset1"
    assert r[0]["relationship"] == "child_of"
    assert r[1]["object_name"] == "dataset3"
    assert r[1]["relationship"] == "child_of"

    assert r[0]["subject_name"] == "dataset2"
    assert r[1]["subject_name"] == "dataset2"

    assert r[0]["subject_type"] == "dataset"
    assert r[1]["subject_type"] == "dataset"
    assert r[0]["object_type"] == "dataset"
    assert r[1]["object_type"] == "dataset"


def test_get_relationships_by_so(app_context):
    r = get_relationships("dataset2", "dataset3", None)
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset2"
    assert r[0]["object_name"] == "dataset3"
    assert r[0]["relationship"] == "child_of"

    r = get_relationships("dataset3", "dataset2", None)
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset3"
    assert r[0]["object_name"] == "dataset2"
    assert r[0]["relationship"] == "parent_of"


def test_get_relationships_by_sr(app_context):
    r = get_relationships("dataset2", None, "parent_of")
    assert len(r) == 0

    r = get_relationships("dataset1", None, "parent_of")
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset1"
    assert r[0]["object_name"] == "dataset2"
    assert r[0]["relationship"] == "parent_of"

    r = get_relationships("dataset3", None, "parent_of")
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset3"
    assert r[0]["object_name"] == "dataset2"
    assert r[0]["relationship"] == "parent_of"


def test_get_relationships_by_sro(app_context):
    r = get_relationships("dataset2", "dataset3", "parent_of")
    assert len(r) == 0
    r = get_relationships("dataset1", "dataset2", "parent_of")
    assert len(r) == 1


def test_create_relationship(app_context):
    r = create_relationship("dataset1", "dataset4", "linked_from", comment="test11")
    assert r is not None
    assert r["subject_name"] == "dataset1"
    assert r["object_name"] == "dataset4"
    assert r["relationship"] == "linked_from"
    assert r["comment"] == "test11"

    # read
    r = get_relationships("dataset1", "dataset4", "linked_from")
    assert len(r) == 1
    r = get_relationships("dataset4", "dataset1", "links_to")
    assert len(r) == 1

    delete_relationship("dataset1", "dataset4", "linked_from")


#
#  API tests
#


def test_api_get_relationships_s(app_client):
    resp = app_client.get("/api/v2/relationships/dataset2")
    assert resp.status_code == 200
    assert resp.json["success"] is True

    r = resp.json["result"]
    assert len(r) == 2
    r.sort(key=lambda x: x["object_name"])
    assert r[0]["object_name"] == "dataset1"
    assert r[0]["relationship"] == "child_of"
    assert r[1]["object_name"] == "dataset3"
    assert r[1]["relationship"] == "child_of"


def test_api_get_relationships_so(app_client):
    resp = app_client.get("/api/v2/relationships/dataset2/_/dataset3")
    assert resp.status_code == 200
    assert resp.json["success"] is True

    r = resp.json["result"]
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset2"
    assert r[0]["object_name"] == "dataset3"
    assert r[0]["relationship"] == "child_of"

    resp = app_client.get("/api/v2/relationships/dataset3/_/dataset2")
    assert resp.status_code == 200
    assert resp.json["success"] is True

    r = resp.json["result"]
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset3"
    assert r[0]["object_name"] == "dataset2"
    assert r[0]["relationship"] == "parent_of"


def test_api_get_relationships_sr(app_client):
    resp = app_client.get("/api/v2/relationships/dataset2/parent_of")
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]

    assert len(r) == 0
    resp = app_client.get("/api/v2/relationships/dataset1/parent_of")
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset1"
    assert r[0]["object_name"] == "dataset2"
    assert r[0]["relationship"] == "parent_of"


def test_api_get_relationships_sro(app_client):
    resp = app_client.get("/api/v2/relationships/dataset2/parent_of/dataset3")
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]
    assert len(r) == 0

    resp = app_client.get("/api/v2/relationships/dataset1/parent_of/dataset2")
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]
    assert len(r) == 1


def test_api_create_relationships(app_client):
    resp = app_client.post(
        "/api/v2/relationship/dataset1/linked_from/dataset4",
        json={"comment": "test11"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    r = resp.json["result"]
    assert r["subject_name"] == "dataset1"
    assert r["object_name"] == "dataset4"
    assert r["relationship"] == "linked_from"
    assert r["comment"] == "test11"

    # read
    r = get_relationships("dataset1", "dataset4", "linked_from")
    assert len(r) == 1


def test_api_update_relationships(app_client):
    resp = app_client.put(
        "/api/v2/relationship/dataset1/parent_of/dataset2",
        json={"comment": "new comment"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    r = resp.json["result"]
    assert r["subject_name"] == "dataset1"
    assert r["object_name"] == "dataset2"
    assert r["relationship"] == "parent_of"
    assert r["comment"] == "new comment"

    # read
    resp = app_client.get(
        "/api/v2/relationships/dataset1/parent_of/dataset2",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]
    assert len(r) == 1
    assert r[0]["subject_name"] == "dataset1"
    assert r[0]["object_name"] == "dataset2"
    assert r[0]["relationship"] == "parent_of"
    assert r[0]["comment"] == "new comment"


def test_api_delete_relationship(app_client):
    resp = app_client.delete(
        "/api/v2/relationship/dataset3/depends_on/dataset4",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    resp = app_client.get(
        "/api/v2/relationships/dataset3/depends_on/dataset4",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]
    assert len(r) == 0

    # Check that deleting again succeeds
    resp = app_client.delete(
        "/api/v2/relationship/dataset3/depends_on/dataset4",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    # Now delete an inverted relationship
    resp = app_client.delete(
        "/api/v2/relationship/dataset1/parent_of/dataset2",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True
    resp = app_client.get(
        "/api/v2/relationships/dataset1/parent_of/dataset2",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True


def test_api_create_multiple_relationships(app_client):
    resp = app_client.post(
        "/api/v2/relationship/dataset1/linked_from/dataset4",
        json={"comment": "this is comment1"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    resp = app_client.post(
        "/api/v2/relationship/dataset1/dependency_of/dataset4",
        json={"comment": "this is comment2"},
    )
    assert resp.status_code == 200

    resp = app_client.post(
        "/api/v2/relationship/dataset1/has_derivation/dataset4",
        json={"comment": "this is comment3"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    resp = app_client.get(
        "/api/v2/relationships/dataset1/_/dataset4",
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True
    r = resp.json["result"]
    assert len(r) == 3
    r.sort(key=lambda x: x["relationship"])
    assert r[0]["relationship"] == "dependency_of"
    assert r[1]["relationship"] == "has_derivation"
    assert r[2]["relationship"] == "linked_from"

    assert r[0]["comment"] == "this is comment2"
    assert r[1]["comment"] == "this is comment3"
    assert r[2]["comment"] == "this is comment1"


def test_api_create_existing_relationship_is_update(app_client):
    resp = app_client.post(
        "/api/v2/relationship/dataset1/linked_from/dataset4",
        json={"comment": "this is comment1"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    resp = app_client.post(
        "/api/v2/relationship/dataset1/linked_from/dataset4",
        json={"comment": "this is comment2"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    r = get_relationships("dataset1", "dataset4", "linked_from")
    assert len(r) == 1
    assert r[0]["comment"] == "this is comment2"


def test_api_update_nonexisting_relationship_is_404(app_client):
    resp = app_client.put(
        "/api/v2/relationship/dataset1/linked_from/dataset4",
        json={"comment": "this is comment1"},
    )
    assert resp.status_code == 404
    assert resp.json["success"] is False


def test_create_relationship_with_nonexisting_subject_is_404(app_client):
    resp = app_client.post(
        "/api/v2/relationship/dataset99/linked_from/dataset4",
        json={"comment": "this is comment1"},
    )
    assert resp.status_code == 404
    assert resp.json["success"] is False


def test_create_relationship_with_nonexisting_object_is_404(app_client):
    resp = app_client.post(
        "/api/v2/relationship/dataset1/linked_from/dataset99",
        json={"comment": "this is comment1"},
    )
    assert resp.status_code == 404
    assert resp.json["success"] is False


def test_create_relationship_with_nonexisting_relationship_is_400(app_client):
    resp = app_client.post(
        "/api/v2/relationship/dataset1/unknown_relationship/dataset4",
        json={"comment": "this is comment1"},
    )
    assert resp.status_code == 400
    assert resp.json["success"] is False
