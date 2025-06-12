from exceptions import DataError, NotFoundError, ConflictError
import uuid
import utils
import sql_utils
from apiflask import Schema, fields, validators


class LicenseSchema(Schema):
    id = fields.UUID(dump_only=True)
    key = fields.String(
        required=True,
        validate=validators.Regexp(
            r"^[a-z0-9_-]+$",
            error="Key must be lowercase, contain no spaces, and only hyphens or underscores are allowed.",
        ),
    )
    title = fields.String(required=True)
    url = fields.String(allow_none=True, dump_default=None)
    description = fields.String(allow_none=True, dump_default=None)
    image_url = fields.String(allow_none=True, load_default=None)
    osi_approved = fields.Boolean(
        required=False, dump_default=False, load_default=False
    )
    open_data_approved = fields.Boolean(
        required=False, dump_default=False, load_default=False
    )
    metadata_created = fields.DateTime(
        dump_only=True, allow_none=True, dump_default=None
    )
    metadata_modified = fields.DateTime(
        dump_only=True, allow_none=True, dump_default=None
    )


class LicenseUpdateSchema(Schema):
    title = fields.String(required=False, allow_none=True)
    url = fields.String(allow_none=True, dump_default=None)
    description = fields.String(allow_none=True, dump_default=None)
    image_url = fields.String(allow_none=True, load_default=None)
    osi_approved = fields.Boolean(
        required=False, dump_default=False, load_default=False
    )
    open_data_approved = fields.Boolean(
        required=False, dump_default=False, load_default=False
    )


class LicenseEntity:

    def __init__(self):
        self.name = "license"
        self.schema = LicenseSchema()

    def validate(self, eid: str):
        l = self.get(eid)
        if l is None:
            raise NotFoundError(f"License with ID: {eid} was not found")
        return l

    def fetch_entities(self):
        """Fetch all licenses from the database."""
        licenses = sql_utils.license_fetch_all()
        return [self.schema.dump(l) for l in licenses] if licenses else []

    def list_entities(self):
        """List all licenses."""
        licenses = sql_utils.license_list_all()
        return licenses if licenses else []

    def get_by_key(self, key: str):
        """Get License by its key."""
        l = sql_utils.license_get_by_key(key)
        if l is None:
            raise NotFoundError(f"License with key: {key} was not found")
        return self.schema.dump(l)

    def get(self, identifier: str):
        """Get License by its ID or key."""
        if utils.is_valid_uuid(identifier):
            eid = identifier
        else:
            return self.get_by_key(identifier)

        l = sql_utils.license_get_by_id(eid)
        if l is None:
            raise NotFoundError(f"License with ID: {eid} was not found")
        return self.schema.dump(l)

    def create(self, **spec: dict):
        """Create a new license."""

        if not spec.get("key") or not spec.get("title"):
            raise DataError("License must have a key and a title.")
        try:
            # Check if the license already exists
            self.get_by_key(spec["key"])
            raise ConflictError(f"License with key: {spec['key']} already exists.")
        except NotFoundError:
            if sql_utils.license_create(str(uuid.uuid4()), **spec):
                return self.get_by_key(spec["key"])
            else:
                raise RuntimeError("Failed to create the license in the database.")

    def patch(self, eid: str, **spec: dict):
        """Patch an existing license."""
        lid = self.validate(eid)["id"]
        sql_utils.license_patch(lid, **spec)
        return self.get(lid)

    def delete(self, eid: str):
        """Delete a license."""
        lid = self.validate(eid)["id"]
        if sql_utils.license_delete(lid):
            return {}
        else:
            raise RuntimeError("Failed to delete the license from the database.")


LICENSE = LicenseEntity()
