import json

import pytest
import werkzeug

werkzeug.__version__ = "3.1.3"

import schema
from cutils import DATASET, GROUP, ORGANIZATION, VOCABULARY, Entity
from tags import get_vocabulary


def test_dummy_app(app):
    for k, v in app.config.items():
        if k == "settings":
            continue
        print(k, "=", v)
    for k, v in app.config["settings"].items():
        print("setting  ", k, "=", v)


def test_entity_creation(app):
    e = Entity(
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

    e = Entity(
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
    e = Entity(
        "dset", "dsets", schema.DatasetSchema(), schema.DatasetSchema(partial=True)
    )

    assert e.save_extras_to_ckan(input_data) == expected_output


@pytest.mark.parametrize("expected_output, input_data", extras_pairs)
def test_load_extras(input_data, expected_output):
    e = Entity(
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
    e = Entity(
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
        except:
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
    # breakpoint()

    response = werkzeug.test.TestResponse = client.get(
        f"/api/v2/{DATASET.collection_name}",
        headers={"Authorization": f"Bearer {credentials.token}"},
    )

    print(response, response.json)

    assert response.status_code == 200
    match response.json:
        case {"success": True, "result": [*elements]}:
            items = len(elements)
        case _:
            assert False
    print("There are", len(elements), "datasets")
