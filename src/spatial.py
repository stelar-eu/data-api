#
# Spatial support for entities.
#

from typing import Any, Iterable

import geojson
from apiflask.fields import Field, Raw
from marshmallow import ValidationError, types


class Spatial(Field):
    """A field for storing spatial data in CKAN."""

    def _serialize(self, value, attr, obj, **kwargs):
        """This method converts the GeoJSON object to a string."""
        if value is None:
            return None
        else:
            return geojson.dumps(value)

    def _deserialize(self, value, attr, data, **kwargs):
        """This method converts the string to a GeoJSON object."""
        return geojson.loads(value)


class GeoJSONGeomValidator(types.Validator):
    def __call__(self, value: Any):
        try:
            # return geojson.loads(value).is_valid
            return geojson.GeoJSON.to_instance(value).is_valid
        except Exception:
            return False


class GeoJSONGeom(Field):
    """A field for the dataset 'spatial' attribute."""

    def __init__(
        self,
        validate: types.Validator | Iterable[types.Validator] | None = None,
        **kwargs
    ):
        gjv = GeoJSONGeomValidator()
        if validate is None:
            validate = [gjv]
        elif isinstance(validate, types.Validator):
            validate = [gjv, validate]
        else:
            validate = [gjv, *validate]
        super().__init__(validate=validate, **kwargs)
