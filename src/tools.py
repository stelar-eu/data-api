from apiflask import fields, validators
from marshmallow import EXCLUDE

from entity import PackageCKANSchema, PackageEntity, PackageSchema


class ToolCKANSchema(PackageCKANSchema):
    git_repository = fields.String(allow_none=True, data_key="url")
    programming_language = fields.String(allow_none=True, load_default=None)

    inputs = fields.Raw(load_default={})
    outputs = fields.Raw(load_default={})
    parameters = fields.Raw(load_default={})

    # Use resources to represent images
    images = fields.Raw(data_key="resources", load_only=True)

    class Meta(PackageCKANSchema.Meta):
        exclude = ["title", "url"]
        unknown = EXCLUDE
        extra_attributes = ["programming_language", "inputs", "outputs", "parameters"]


class ToolSchema(PackageSchema):
    programming_language = fields.String(allow_none=True)
    git_repository = fields.String(allow_none=True)
    type = fields.String(validate=validators.Equal("tool"))

    inputs = fields.Dict(keys=fields.String, values=fields.String, dump_default={})
    outputs = fields.Dict(keys=fields.String, values=fields.String, dump_default={})
    parameters = fields.Dict(keys=fields.String, values=fields.String, dump_default={})

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
