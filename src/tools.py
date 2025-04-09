from apiflask import fields, validators
from marshmallow import EXCLUDE

from entity import PackageCKANSchema, PackageEntity, PackageSchema
from backend.registry import quay_request
from qutils import REGISTRY
from schema import NameID

import markdown


class ToolCKANSchema(PackageCKANSchema):
    git_repository = fields.String(allow_none=True, data_key="url")
    programming_language = fields.String(allow_none=True, load_default=None)

    inputs = fields.Raw(load_default={})
    outputs = fields.Raw(load_default={})
    parameters = fields.Raw(load_default={})
    repository = fields.String(allow_none=True, load_default=None)

    # Use resources to represent images
    images = fields.Raw(data_key="resources", load_only=True)

    class Meta(PackageCKANSchema.Meta):
        exclude = ["title", "url"]
        unknown = EXCLUDE
        extra_attributes = [
            "programming_language",
            "inputs",
            "outputs",
            "parameters",
            "repository",
        ]


class ToolSchema(PackageSchema):
    programming_language = fields.String(allow_none=True)
    git_repository = fields.String(allow_none=True)
    type = fields.String(validate=validators.Equal("tool"))

    inputs = fields.Dict(keys=fields.String, values=fields.String, dump_default={})
    outputs = fields.Dict(keys=fields.String, values=fields.String, dump_default={})
    parameters = fields.Dict(keys=fields.String, values=fields.String, dump_default={})

    # Use resources to represent images
    images = fields.Raw(dump_only=True)

    repository = fields.String(allow_none=True, dump_only=True)

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

    def load_from_ckan(self, raw_obj):
        obj = super().load_from_ckan(raw_obj)
        if obj.get("notes"):
            raw = obj.get("notes").encode("utf-8").decode("unicode_escape")
            obj["readme"] = markdown.markdown(raw, extensions=["fenced_code"])
        tool = self._enhance_from_registry(obj)
        return tool

    def create(self, init_data):
        # If the repository name is provided, create the repository in the registry
        init_data["repository"] = init_data["name"]
        REGISTRY.create_repository(
            repository=init_data["repository"],
            notes=init_data.get("notes", ""),
        )
        return super().create(init_data)

    def _enhance_from_registry(self, package: dict):
        """
        Enhance the tool entity with additional information from the registry.
        This method is called after the entity is created.
        """
        if "repository" not in package or package["repository"] is None:
            return package
        try:
            images = REGISTRY.get_repository_tags(package["repository"])
        except:
            return package
        package.update({"images": images})
        return package


TOOL = ToolEntity()
