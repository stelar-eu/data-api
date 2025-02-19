from apiflask import fields, validators
from marshmallow import EXCLUDE

from entity import PackageCKANSchema, PackageEntity, PackageSchema


class ToolCKANSchema(PackageCKANSchema):
    programming_language = fields.String(allow_none=True, optional=True)
    git_repository = fields.String(allow_none=True, optional=True, data_key="url")

    # Use resources to represent images
    images = fields.Raw(data_key="resources", load_only=True)

    class Meta:
        exclude = ["title", "url"]
        unknown = EXCLUDE
        extra_attributes = ["programming_language"]


class ToolSchema(PackageSchema):
    programming_language = fields.String(allow_none=True, optional=True)
    git_repository = fields.String(allow_none=True, optional=True, data_key="url")
    type = fields.String(validate=validators.Equal("dataset"))

    # Use resources to represent images
    images = fields.Raw(dump_only=True)

    class Meta:
        exclude = ["title", "url"]


class ToolEntity(PackageEntity):
    def __init__(self):
        super().__init__(
            "tool",
            "tools",
            ToolSchema(),
            ToolSchema(partial=True),
            package_type="tool",
            ckan_schema=ToolCKANSchema(),
        )


TOOL = ToolEntity()
