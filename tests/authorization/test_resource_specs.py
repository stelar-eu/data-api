import pytest
import authz_module
from authz_module import (
    AttrSpec,
    GMspec,
    OMSpec,
    UMspec,
)
from flask import g
import kutils as ku


def fake_current_user():
    return {"sub": "test_user_uuid"}


def fake_ckan_request(method, **kwargs):
    # For testing, return a simple dict.
    if method == "package_show":
        if kwargs.get("id") == "test_dataset_resource":
            return {
                "id": kwargs.get("id", "unknown"),
                "type": "dataset",
                "groups": [{"name": "group1"}],
                "organization": {"name": "org1"}
            }
        elif kwargs.get("id") == "test_workflow_resource":
            return {
                "id": kwargs.get("id", "unknown"),
                "type": "workflow",
                "groups": [{"name": "group1"}]
            }
        elif kwargs.get("id") == "test_process_resource":
            return {
                "id": kwargs.get("id", "unknown"),
                "type": "process",
                "groups": [{"name": "group1"}]
            }
        elif kwargs.get("id") == "test_tool_resource":
            return {
                "id": kwargs.get("id", "unknown"),
                "type": "tool",
                "groups": [{"name": "group1"}]
            }

    elif method.endswith("_show"):
        return {"id": kwargs.get("resource", "unknown"), "type": method.replace("_show", "")}
    elif method == "member_list":
        if kwargs.get("id") == "org1":
            return [["test_dataset_resource","main"],["test_workflow_resource","secondary"],["test_group_resource","subgroup"]]
        else:
            return [["test_dataset_resource","main"],["test_workflow_resource","secondary"],["test_group_resource","subgroup"],["test_user_uuid","maintainer"]]
    return {}


def test_attr_spec():
    # Set up the global "context" variable expected by AttrSpec.
    
    spec = AttrSpec(attr="id", operation="equals", value="test_uid")
    resource = {"id": "test_uid"}
    assert spec(resource)

    resource_wrong = {"id": "wrong"}
    assert not spec(resource_wrong)

    spec = AttrSpec(attr="id", operation="like", value="test_*")
    resource = {"id": "test_uid"}
    assert spec(resource)

    resource_wrong = {"id": "test-wrong"}
    assert not spec(resource_wrong)

    with pytest.raises(ValueError):
        AttrSpec(attr="id", operation="nonexistent", value="value")

def test_gmspec(monkeysession, app):
    # Monkeypatch fetch_resource to return resource unchanged.
    # monkeypatch.setattr(GMspec, "fetch_resource", lambda self, resource: resource)
    spec = GMspec(type="dataset", group="foo1", capacity="main")
    # Override check_type, check_capacity, and check_group for controlled testing.
    monkeysession.setattr(spec, "check_type", lambda r: True)
    monkeysession.setattr(spec, "check_capacity", lambda r: True)
    monkeysession.setattr(spec, "check_group", lambda r: True)
    
    # resource = {"type": "server", "groups": [{"name": "group1"}], "capacity": "test_id"}
    # resource = "d524f695-4714-449d-8b5d-078252c2a107"
    resource = {}
    assert spec(resource) is True

    # Simulate group check failure.
    monkeysession.setattr(spec, "check_group", lambda r: False)
    # resource = "0400c522-c99f-436f-aab8-799f6fe3720b"
    assert spec(resource) is False

def test_gmspec_with_fake_data(app):
    
    with app.app_context():
        g.entity = "dataset"

        # # Replace ckan_request in our module with the fake.
        authz_module.ckan_request = fake_ckan_request
        
        spec = GMspec(type="dataset", group="group1", capacity="main")
        resource = "test_dataset_resource"
        assert spec(resource)

        g.entity = "workflow"

        spec = GMspec(type="workflow", group="group1", capacity="secondary")
        resource = "test_workflow_resource"
        assert spec(resource)

        g.entity = "group"

        spec = GMspec(type="group", group="group1", capacity="subgroup")
        resource_3 = "test_group_resource"
        assert spec(resource_3)

# def test_gmspec_with_real_data(app):
#     with app.app_context():
#         g.entity = "dataset"
        
#         spec = GMspec(type="dataset", group="group1", capacity="main")
#         resource = "test_resource"
#         assert spec(resource)

#         spec = GMspec(type="dataset", group="group2", capacity="main")
#         assert spec(resource)


def test_omspec(monkeysession, app_context):
    # monkeysession.setattr(OMSpec, "fetch_resource", lambda self, resource: resource)
    spec = OMSpec(type="storage", org="org1", capacity="test_id")
    monkeysession.setattr(spec, "check_org", lambda r: True)
    monkeysession.setattr(spec, "check_type", lambda r: True)
    monkeysession.setattr(spec, "check_capacity", lambda r: True)
    
    resource = {}
    assert spec(resource) is True

    monkeysession.setattr(spec, "check_org", lambda r: False)
    assert spec(resource) is False

def test_omspec_with_fake_data(app):
    
    with app.app_context():
        g.entity = "dataset"

        # # Replace ckan_request in our module with the fake.
        authz_module.ckan_request = fake_ckan_request
        
        spec = OMSpec(type="dataset", org="org1", capacity="main")
        resource = "test_dataset_resource"
        assert spec(resource)

        g.entity = "workflow"

        spec = OMSpec(type="workflow", org="org1", capacity="secondary")
        resource = "test_workflow_resource"
        assert spec(resource)

        g.entity = "group"

        spec = OMSpec(type="group", org="org1", capacity="subgroup")
        resource_3 = "test_group_resource"
        assert spec(resource_3)


def test_umspec(monkeysession):

    spec = UMspec(group="user", capacity="main")

    monkeysession.setattr(spec, "check_group", lambda r: True)
    monkeysession.setattr(spec, "check_capacity", lambda r: True)

    resource = {}
    # resource = DummyResource(group="user", capacity="main")
    assert spec(resource)

    # resource_bad = DummyResource(group="admin", capacity="main")
    resource_bad = {}
    monkeysession.setattr(spec, "check_group", lambda r: False)
    assert not spec(resource_bad)

def test_umspec_with_fake_data(app):
    with app.app_context():

        ku.current_user = fake_current_user
        authz_module.ckan_request = fake_ckan_request

        spec = UMspec(group="group1", capacity="maintainer")
        resource = "test_resource"
        assert spec(resource)

        spec = UMspec(group="admin", capacity="main")
        assert not spec(resource)