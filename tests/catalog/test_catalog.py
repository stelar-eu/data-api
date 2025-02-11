import datetime
import json

import pytest
import werkzeug
from marshmallow import EXCLUDE

import schema
from cutils import DATASET, GROUP, ORGANIZATION, VOCABULARY
from entity import CKANEntity, Entity, PackageCKANSchema
from tags import get_vocabulary

#  The followng fixes a bug in FlaskClient !!
# werkzeug.__version__ = "3.1.3"


def test_dummy_app(app):
    for k, v in app.config.items():
        if k == "settings":
            continue
        print(k, "=", v)
    for k, v in app.config["settings"].items():
        print("setting  ", k, "=", v)


def test_entity_creation(app):
    e = CKANEntity(
        "dset", "dsets", schema.DatasetSchema(), schema.DatasetSchema(partial=True)
    )

    assert e.name == "dset"
    assert e.collection_name == "dsets"
    assert e.ckan_name == "dset"
    assert e.ckan_api_create == "dset_create"
    assert e.ckan_api_list == "dset_list"

    assert not e.creation_schema.partial
    assert e.update_schema.partial

    assert e.has_extras
    assert not e.has_tags

    assert "update" in e.operations
    assert "patch" in e.operations

    e = CKANEntity(
        "tool",
        "tools",
        schema.DatasetSchema(),
        schema.DatasetSchema(partial=True),
        ckan_name="package",
    )
    assert e.ckan_name == "package"
    assert e.has_extras and e.has_tags
    assert all(op in e.operations for op in Entity.OPERATIONS)


extras_pairs = [
    ({"a": "hello"}, [{"key": "a", "value": '"hello"'}]),
    ({"a": 10.2}, [{"key": "a", "value": "10.2"}]),
    ({}, []),
    (
        {"a": True, "b": -20},
        [{"key": "a", "value": "true"}, {"key": "b", "value": "-20"}],
    ),
    ({"a": {"nested": 1}}, [{"key": "a", "value": json.dumps({"nested": 1})}]),
]


@pytest.mark.parametrize("input_data, expected_output", extras_pairs)
def test_save_extras(input_data, expected_output):
    e = CKANEntity(
        "dset", "dsets", schema.DatasetSchema(), schema.DatasetSchema(partial=True)
    )

    assert e.save_extras_to_ckan(input_data) == expected_output


@pytest.mark.parametrize("expected_output, input_data", extras_pairs)
def test_load_extras(input_data, expected_output):
    e = CKANEntity(
        "dset", "dsets", schema.DatasetSchema(), schema.DatasetSchema(partial=True)
    )

    assert e.load_extras_from_ckan(input_data) == expected_output


@pytest.fixture(scope="session")
def thedaltons(app):
    with app.app_context():
        return get_vocabulary("daltons")


def test_get_vocabulary(thedaltons):
    assert thedaltons["name"] == "daltons"


tags_pairs = [
    (["foo"], [{"name": "foo"}]),
    ([], []),
    (["foobar", "aa", "ee"], [{"name": "foobar"}, {"name": "aa"}, {"name": "ee"}]),
    (["daltons:joe"], [{"name": "joe", "vocabulary_id": "daltons"}]),
]


@pytest.fixture(scope="function")
def tagobject(request, thedaltons):
    tagobjlist = request.param
    tagfixedlist = []
    for tagobj in tagobjlist:
        vname = tagobj.get("vocabulary_id")
        if vname is None:
            tagfixedlist.append(tagobj)
        elif vname == "daltons":
            tagfixedlist.append(tagobj | {"vocabulary_id": thedaltons["id"]})
        else:
            # Will fail !
            tagfixedlist.append(tagobj)
    return tagfixedlist


@pytest.mark.parametrize("tagspec, tagobject", tags_pairs, indirect=["tagobject"])
def test_save_tags(tagspec, tagobject, app):
    e = CKANEntity(
        "dset", "dsets", schema.DatasetSchema(), schema.DatasetSchema(partial=True)
    )

    with app.app_context():
        assert e.save_tags_to_ckan(tagspec) == tagobject
        assert e.load_tags_from_ckan(tagobject) == tagspec


@pytest.mark.parametrize(
    "entity",
    [DATASET, GROUP, ORGANIZATION, VOCABULARY],
)
def test_list_entity(entity, app):
    with app.app_context():
        for limit in [1, 2, 4, 8]:
            elist = entity.list_entities(limit=limit, offset=0)

            assert isinstance(elist, list)
            assert len(elist) <= limit

            for e in elist:
                assert isinstance(e, str)


def test_manage_dataset(app):
    with app.app_context():
        try:
            DATASET.delete_entity("test_dataset", purge=True)
        except Exception:
            pass

        # create a dataset
        d = DATASET.create_entity(
            dict(
                owner_org="stelar-klms",
                name="test_dataset",
                title="A test dataset",
                url="s3://testvol/data.txt",
            )
        )

        sch = DATASET.creation_schema
        if callable(sch):
            sch = sch()
        field_names = list(sch.fields.keys())

        assert all(attr in d for attr in field_names)
        eid = d["id"]
        ename = d["name"]

        # update the author
        assert d["author"] != "Homer"
        DATASET.patch_entity(eid, {"author": "Homer"})

        assert DATASET.get_entity(eid)["author"] == "Homer"
        assert DATASET.get_entity(ename)["author"] == "Homer"

        assert d["resources"] == []

        DATASET.delete_entity(eid)


def test_dataset_api(client: werkzeug.Client, credentials):
    response = client.get(
        f"/api/v2/{DATASET.collection_name}",
        headers={"Authorization": f"Bearer {credentials.token}"},
    )

    assert response.status_code == 200
    match response.json:
        case {"success": True, "result": [*elements]}:
            items = len(elements)
        case _:
            assert False
    # print("There are", len(elements), "datasets")


def test_dataset_ckan_schema(DC):
    s = PackageCKANSchema()

    sk = DC.stelar_klms

    try:
        init_args = s.dump(
            dict(
                name="test_dataset_ckan_schema",
                title="Test dataset",
                owner_org="stelar-klms",
                url="s3://testvol/data.txt",
                extras={"a": "10.2"},
                tags=["foo", "bar"],
                metadata_created="2021-09-01T00:00:00",
                license_id="cc-by",
            )
        )

        assert "license_id" not in init_args
        assert "metadata_created" not in init_args
        assert init_args["extras"] == [{"key": "a", "value": "10.2"}]

        resp = DC.package_create(**init_args)
        assert resp["success"]

        # Check a package loaded after creation
        pkg = resp["result"]
        p = s.load(pkg)

        assert p["type"] == "dataset"
        assert p["name"] == "test_dataset_ckan_schema"
        assert p["creator_user_id"] == DC.ckan_admin["id"]

        assert isinstance(p["metadata_created"], datetime.datetime)
        assert isinstance(p["metadata_modified"], datetime.datetime)

        assert p["owner_org"] == DC.stelar_klms["id"]
        assert p["extras"] == {"a": "10.2"}
        assert p["state"] == "active"
        assert p["title"] == "Test dataset"
        assert p["url"] == "s3://testvol/data.txt"
        assert p["private"] is False

        assert isinstance(p["tags"], list)
        assert len(p["tags"]) == 2
        assert set(p["tags"]) == {"foo", "bar"}

        assert not p["author"]
        assert not p["author_email"]
        assert not p["maintainer"]
        assert not p["maintainer_email"]
        assert not p["notes"]
        assert not p["version"]

        assert "licence_id" not in p
        assert "licence_title" not in p
        assert "licence_url" not in p
        assert "num_resources" not in p
        assert "num_tags" not in p
        assert "isopen" not in p
        assert "organization" not in p
        assert "relationships_as_object" not in p
        assert "relationships_as_subject" not in p

        assert p["resources"] == []
        assert p["groups"] == []

        # -------------------------
        # Check the patching
        # -------------------------
        patch_args = s.dump(dict(author="Homer", title="The Odyssey"))

        assert patch_args.keys() == {"author", "title"}

        resp = DC.package_patch(id=p["id"], **patch_args)
        assert resp["success"]
        q = s.load(resp["result"])

        assert q["author"] == "Homer"
        assert q["title"] == "The Odyssey"

        assert set(q.keys()) == set(p.keys())
        for k in set(q.keys()) - {"author", "title", "metadata_modified", "tags"}:
            assert q[k] == p[k]
        assert set(q["tags"]) == set(p["tags"])

        # -------------------------
        #  Check the get
        # -------------------------
        resp = DC.package_show(id=p["id"])
        assert resp["success"]
        r = s.load(resp["result"])

        assert set(q.keys()) == set(r.keys())
        for k in set(q.keys()) - {"author", "title", "metadata_modified", "tags"}:
            assert q[k] == r[k]
        assert set(q["tags"]) == set(r["tags"])

    finally:
        assert DC.dataset_purge(id="test_dataset_ckan_schema")["success"]


def test_dataset_ckan_schema_trans(DC):
    s = PackageCKANSchema()

    obj1 = dict(
        id="asdasaddads",
        type="dataset",
        name="test_dataset_ckan_schema",
        title="Test dataset",
        owner_org=DC.stelar_klms["id"],
        url="s3://testvol/data.txt",
        extras={"a": "10.2"},
        tags=["foo", "bar"],
        metadata_created="2021-09-01T00:00:00",
        license_id="cc-by",
    )

    c1 = s.dump(obj1)

    # Notice that 'metadata_created' are not in c1
    # since they are marked as 'load_only'.
    #
    # Also, 'license_id' is not in c1, since it is not in the schema
    assert set(c1.keys()) == {
        "id",
        "type",
        "name",
        "title",
        "owner_org",
        "url",
        "extras",
        "tags",
    }


def test_delete_attr_from_ckan_schema(DC):
    class MySchema(PackageCKANSchema):
        class Meta:
            exclude = ["title", "author"]
            unknown = EXCLUDE
            pass

    s = MySchema()

    resp = DC.package_show(id="package4")
    assert resp["success"]
    pkg = resp["result"]
    obj = s.load(pkg)

    assert "title" not in obj
    assert "author" not in obj
    for f in PackageCKANSchema().fields.keys():
        if f not in ["title", "author"]:
            assert f in obj
