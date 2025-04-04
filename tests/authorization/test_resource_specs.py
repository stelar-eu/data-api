import pytest
from flask import g

import authz_module
import kutils as ku
from authz_module import AttrSpec, GMspec, Resource, UMspec


def fake_current_user():
    return {"sub": "test_user_uuid"}


def fake_fetch_user_group_members(group, is_org):
    return [["test_user_uuid", "maintainer"]]


def fake_fetch_group_members(group, resource, is_org):
    return [
        ["test_dataset_resource", "main"],
        ["test_workflow_resource", "secondary"],
        ["test_group_resource", "subgroup"],
    ]


def fake_fetch_resource(resource):
    if resource.payload == "test_dataset_resource":
        return {
            "id": "test_dataset_resource",
            "type": "dataset",
            "groups": [{"name": "group1"}],
            "organization": {"name": "org1"},
        }
    elif resource.payload == "test_workflow_resource":
        return {
            "id": "test_workflow_resource",
            "type": "workflow",
            "groups": [{"name": "group1"}],
        }
    elif resource.payload == "test_group_resource":
        return {
            "id": "test_group_resource",
            "type": "group",
            "groups": [{"name": "group1"}],
        }
    elif resource.payload == "test_user_uuid":
        return {"id": "test_user_uuid", "type": "user", "groups": [{"name": "group1"}]}
    return {}


def test_attr_spec():
    # Set up the global "context" variable expected by AttrSpec.
    from authz_module import Resource

    spec = AttrSpec(attr="id", operation="equals", value="test_uid")
    resource = Resource(payload={"id": "test_uid"}, entity="dataset")
    assert spec(resource)

    resource_wrong = Resource(payload={"id": "wrong"}, entity="dataset")
    assert not spec(resource_wrong)

    spec = AttrSpec(attr="id", operation="like", value="test_*")
    resource = Resource(payload={"id": "test_uid"}, entity="dataset")
    assert spec(resource)

    resource_wrong = Resource(payload={"id": "test-wrong"}, entity="dataset")
    assert not spec(resource_wrong)

    with pytest.raises(ValueError):
        AttrSpec(attr="id", operation="nonexistent", value="value")


def test_gmspec(monkeysession, app):
    # Monkeypatch fetch_resource to return resource unchanged.
    # monkeypatch.setattr(GMspec, "fetch_resource", lambda self, resource: resource)
    spec = GMspec(type="dataset", group="foo1", capacity="main", is_org=False)
    # Override check_type, check_capacity, and check_group for controlled testing.
    monkeysession.setattr(spec, "check_type", lambda r: True)
    monkeysession.setattr(spec, "check_capacity", lambda r: True)
    monkeysession.setattr(spec, "check_group", lambda r: True)

    resource = {}
    assert spec(resource)

    # Simulate group check failure.
    monkeysession.setattr(spec, "check_group", lambda r: False)
    # resource = "0400c522-c99f-436f-aab8-799f6fe3720b"
    assert not spec(resource)


def test_gmspec_with_fake_data(app):
    with app.app_context():
        from authz_module import Resource

        # # Replace ckan_request in our module with the fake.
        authz_module.fetch_group_members = fake_fetch_group_members
        authz_module.fetch_resource = fake_fetch_resource

        spec = GMspec(type="dataset", group="group1", capacity="main", is_org=False)
        resource = Resource(payload="test_dataset_resource", entity="dataset")
        assert spec(resource)

        spec = GMspec(
            type="workflow", group="group1", capacity="secondary", is_org=False
        )
        resource = Resource(payload="test_workflow_resource", entity="workflow")
        assert spec(resource)

        spec = GMspec(type="group", group="group1", capacity="subgroup", is_org=False)
        resource_3 = Resource(payload="test_group_resource", entity="group")
        assert spec(resource_3)


# def test_gmspec_with_real_data(app):
#     with app.app_context():
#         g.entity = "dataset"

#         spec = GMspec(type="dataset", group="group1", capacity="main")
#         resource = "test_resource"
#         assert spec(resource)

#         spec = GMspec(type="dataset", group="group2", capacity="main")
#         assert spec(resource)


def test_umspec(monkeysession):
    spec = UMspec(group="user", org=None, capacity="main")

    monkeysession.setattr(spec, "check_group", lambda r: True)
    monkeysession.setattr(spec, "check_capacity", lambda r: True)

    resource = {}
    assert spec(resource)

    resource_bad = {}
    monkeysession.setattr(spec, "check_group", lambda r: False)
    assert not spec(resource_bad)


def test_umspec_with_fake_data(app, monkeypatch):
    # Monkeypatch the current_user and fetch_user_group_members functions.
    monkeypatch.setattr(ku, "current_user", fake_current_user)
    monkeypatch.setattr(
        authz_module, "fetch_user_group_members", fake_fetch_user_group_members
    )

    with app.app_context():
        ku.current_user = fake_current_user
        authz_module.fetch_user_group_members = fake_fetch_user_group_members

        spec = UMspec(group="group1", org=None, capacity="maintainer")
        resource = {}
        assert spec(resource)

        spec = UMspec(group="admin", org=None, capacity="main")
        assert not spec(resource)
