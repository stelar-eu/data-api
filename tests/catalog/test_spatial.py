import geojson
import jmespath
import pytest

from cutils import DATASET, DatasetCKANSchema


def test_schema_encode_spatial_data():
    s = DatasetCKANSchema(partial=True)

    point = {"type": "Point", "coordinates": [1, 2]}

    out = s.dump({"spatial": point})

    assert out["extras"]
    assert out["extras"][0]["key"] == "spatial"
    assert "spatial" not in out
    assert isinstance(out["extras"][0]["value"], str)
    assert geojson.loads(out["extras"][0]["value"]) == point

    out = s.dump({"spatial": None})
    assert out["extras"]
    assert out["extras"][0]["key"] == "spatial"
    assert out["extras"][0]["value"] is None
    assert "spatial" not in out


def test_schema_encode_spatial_nodata():
    s = DatasetCKANSchema(partial=True)

    # No mention of spatial data
    out = s.dump({"extras": {"foo": "bar"}})
    assert out == {"extras": [{"key": "foo", "value": '"bar"'}]}
    assert "spatial" not in out

    out = s.dump({"extras": {"foo": "bar"}})
    assert out == {"extras": [{"key": "foo", "value": '"bar"'}]}
    assert "spatial" not in out


def dump_for_update(ckan_schema, update_data, curextras):
    extras_present = "extras" in update_data
    if extras_present or any(
        attr in update_data for attr in ckan_schema.opts.extra_attributes
    ):
        update_extras = update_data.setdefault("extras", {})
        # Note that we are purposely using a name with spaces...
        update_extras["current extras object"] = curextras
        update_extras["extras update present"] = extras_present
    return ckan_schema.dump(update_data)


def assert_equal_extras_lists(a, b):
    # Compare two lists of extras dicts
    # The order of the extras is not important
    a = sorted(a, key=lambda x: x["key"])
    b = sorted(b, key=lambda x: x["key"])
    assert a == b


def test_schema_encode_spatial_update_data():
    s = DatasetCKANSchema(partial=True)

    point1 = {"type": "Point", "coordinates": [1, 2]}
    point1_str = geojson.dumps(point1)
    point2 = {"type": "Point", "coordinates": [2, 1]}
    point2_str = geojson.dumps(point2)

    out = dump_for_update(s, {"spatial": point2}, {"spatial": point1_str})
    assert "spatial" not in out
    assert out["extras"] == [{"key": "spatial", "value": point2_str}]
    assert "spatial" not in out

    out = dump_for_update(s, {"spatial": None}, {"spatial": point1_str})
    assert out["extras"] == [{"key": "spatial", "value": None}]
    assert "spatial" not in out

    out = dump_for_update(s, {"spatial": point2}, {"zfoo": "bar"})
    assert_equal_extras_lists(
        out["extras"],
        [{"key": "spatial", "value": point2_str}, {"key": "zfoo", "value": "bar"}],
    )
    assert "spatial" not in out

    out = dump_for_update(s, {"spatial": None}, {"zfoo": "bar"})
    assert_equal_extras_lists(
        out["extras"],
        [{"key": "spatial", "value": None}, {"key": "zfoo", "value": "bar"}],
    )
    assert "spatial" not in out

    out = dump_for_update(
        s, {"spatial": point2}, {"spatial": point1_str, "zfoo": "bar"}
    )
    assert_equal_extras_lists(
        out["extras"],
        [{"key": "spatial", "value": point2_str}, {"key": "zfoo", "value": "bar"}],
    )
    assert "spatial" not in out

    out = dump_for_update(s, {"spatial": None}, {"spatial": point1_str, "zfoo": "bar"})
    assert_equal_extras_lists(
        out["extras"],
        [{"key": "spatial", "value": None}, {"key": "zfoo", "value": "bar"}],
    )
    assert "spatial" not in out


def test_schema_decode_spatial_data():
    s = DatasetCKANSchema(partial=True)

    point = {"type": "Point", "coordinates": [1, 2]}

    out = s.load({"extras": [{"key": "spatial", "value": geojson.dumps(point)}]})
    assert out["spatial"] == point
    assert out["extras"] == {}

    out = s.load(
        {
            "extras": [
                {"key": "spatial", "value": geojson.dumps(point)},
                {"key": "foo", "value": "bar"},
            ]
        }
    )
    assert out["spatial"] == point
    assert out["extras"] == {"foo": "bar"}

    out = s.load({"extras": [{"key": "nospatial", "value": ""}]})
    assert "spatial" not in out


@pytest.mark.parametrize(
    "geom",
    [
        # Try rectangle
        geojson.Polygon([[(1, 2), (4, 2), (4, 6), (1, 6), (1, 2)]]),
        # Try triangle
        geojson.Polygon([[(1, 2), (4, 2), (4, 6), (1, 2)]]),
        # Try rectangle with hole
        geojson.Polygon(
            [
                [(1, 2), (4, 2), (4, 6), (1, 6), (1, 2)],
                [(2, 3), (3, 3), (3, 5), (2, 5), (2, 3)],
            ]
        ),
        # Try line
        geojson.LineString([(1, 2), (4, 2), (4, 6), (1, 6)]),
        # Try multipoint
        geojson.MultiPoint([(1, 2), (4, 2), (4, 6), (1, 6)]),
        # Note: single points DO NOT WORK!!
        # The search fails to return them!
    ],
)
def test_create_spatial_dataset(app_context, geom):
    try:
        DATASET.delete("test-dataset", purge=True)
    except Exception:
        pass

    # Create a test dataset with spatial data
    assert geom.is_valid

    d = DATASET.create(
        {
            "name": "test-dataset",
            "owner_org": "stelar-klms",
            "title": "Test Dataset",
            "spatial": geom,
            "extras": {"pytest": "temporary"},
        }
    )

    assert d["name"] == "test-dataset"
    assert d["title"] == "Test Dataset"  # Title is not spatial data
    assert d["spatial"] == geom
    assert d["extras"] == {"pytest": "temporary"}  # Extras is not spatial data

    # Check that the dataset can be retrieved
    d = DATASET.get("test-dataset")
    assert d["name"] == "test-dataset"
    assert d["title"] == "Test Dataset"
    assert d["spatial"] == geom
    assert d["extras"] == {"pytest": "temporary"}

    # Check that the dataset can be found by normal search
    search = DATASET.search(dict(q="name:test-dataset", fl=["name"]))
    assert "test-dataset" in jmespath.search("results[*].name", search)

    # Check that the dataset can be found by spatial search
    search = DATASET.search(dict(bbox=[-180, -90, 180, 90], fl=["name"]))
    assert "test-dataset" in jmespath.search("results[*].name", search)

    # Delete the spatial attribute
    d = DATASET.patch("test-dataset", {"spatial": None})
    assert d["spatial"] is None

    # Check that the dataset cannot be found by spatial search
    search = DATASET.search(dict(bbox=[-180, -90, 180, 90], fl=["name"]))
    assert "test-dataset" not in jmespath.search("results[*].name", search)

    DATASET.delete("test-dataset", purge=True)
