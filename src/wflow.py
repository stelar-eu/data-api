"""
    Workflows:
    ==========

    These are CKAN packages with a type of 'workflow'. They are used to define the structure of a workflow,
    which is a sequence of tasks that need to be executed, as well as other metadata.
"""

from apiflask import fields, validators
from marshmallow import EXCLUDE

from entity import PackageCKANSchema, PackageEntity, PackageSchema


class WorkflowCKANSchema(PackageCKANSchema):
    repository = fields.String(allow_none=True, data_key="url")
    executor = fields.String(allow_none=True, load_default=None)

    # Use resources to represent images
    # images = fields.Raw(data_key="resources", load_only=True)

    class Meta:
        exclude = ["url"]
        unknown = EXCLUDE
        extra_attributes = ["executor"]


class WorkflowSchema(PackageSchema):
    type = fields.String(validate=validators.Equal("tool"))
    repository = fields.String(allow_none=True)
    executor = fields.String(allow_none=True)

    class Meta:
        exclude = ["url"]


class WorkflowEntity(PackageEntity):
    def __init__(self):
        super().__init__(
            "workflow",
            "workflows",
            WorkflowSchema(),
            WorkflowSchema(partial=True),
            package_type="workflow",
            ckan_schema=WorkflowCKANSchema(),
        )


WORKFLOW = WorkflowEntity()
