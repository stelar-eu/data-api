from apiflask import Schema
from apiflask.fields import (
    URL,
    Boolean,
    Constant,
    DateTime,
    Dict,
    Float,
    Integer,
    List,
    Nested,
    String,
)
from apiflask.validators import Length, OneOf, Range, Regexp
from marshmallow import INCLUDE, ValidationError, fields, pre_load

from tags import TAGNAME_PATTERN, TAGSPEC_PATTERN

optional_basic_metadata = [
    "version",
    "url",
    "author",
    "author_email",
    "maintainer",
    "maintainer_email",
    "license_id",
    "type",
    "private",
]

# ---------------------------------------------
#  Schema for generic requests and responses
# ---------------------------------------------


class ErrorSpec(Schema):
    type = String(required=True, data_key="__type")
    message = String(required=True)
    detail = Dict(required=False)


class APIErrorResponse(Schema):
    help = URL(required=True)
    # success = Boolean(required=True, validates=Equal(False))
    success = Constant(False)
    error = Nested(ErrorSpec, required=True)


class APIResponse(Schema):
    help = URL(required=True)
    # success = Boolean(required=True, validates=Equal(True))
    success = Constant(True)
    result = Dict(required=True)
    error = Nested(ErrorSpec, required=False)


class DeleteRequest(Schema):
    purge = Boolean(required=False, load_default=False)


class DeleteResponse(APIResponse):
    result = None


class IdListResponse(Schema):
    help = URL(required=True)
    success = Boolean(required=True)
    # Use fields that are conditionally required depending on success
    result = List(String(), required=False)


class MemberListResponse(Schema):
    help = URL(required=True)
    success = Boolean(required=True)
    # Use fields that are conditionally required depending on success
    result = List(List(String()), required=True)


class EntityListResponse(Schema):
    help = URL(required=True)
    success = Boolean(required=True)

    # Use fields that are conditionally required depending on success
    result = List(Dict(), required=False)


class PaginationParameters(Schema):
    limit = Integer(required=False, validate=Range(min=1))
    offset = Integer(required=False, validate=Range(min=0))


class LineageForwardBoolean(Schema):
    forward = Boolean(required=False)
    depth = Integer(required=False, validate=Range(min=0), load_default=None)


class LLMSearchQuery(Schema):
    q = String(
        required=True,
        metadata={
            "example": "I am looking for datasets on climate change mainly in Europe"
        },
    )
    limit = Integer(required=False, validate=Range(min=0), load_default=10)


class NameID(String):
    """Datasets, groups and organizations, etc, have name field which is unique and immutable."""

    def __init__(self, required=True, **kwargs):
        super().__init__(
            required=required, validate=[Regexp(r"^[a-z0-9_-]{2,100}$")], **kwargs
        )


class TagName(String):
    """Datasets, groups and organizations, etc, have name field which is unique and immutable."""

    def __init__(self, required=True, **kwargs):
        super().__init__(
            required=required, validate=[Regexp(TAGNAME_PATTERN.pattern)], **kwargs
        )


class TagSpec(String):
    """Datasets, groups and organizations, etc, have name field which is unique and immutable."""

    def __init__(self, required=True, **kwargs):
        super().__init__(
            required=required, validate=[Regexp(TAGSPEC_PATTERN.pattern)], **kwargs
        )


class EntityCreationRequest(Schema):
    """A base class for creation requests of named entities."""

    name = NameID()


class DatasetSchema(Schema):
    name = NameID()

    tags = List(String, required=False)
    extras = Dict(required=False)
    state = String(required=False, validate=OneOf(["draft", "active", "deleted"]))

    owner_org = String(required=True)

    title = String(required=False)
    notes = String(required=False, validate=Length(0, 10000), allow_none=True)
    author = String(required=False, allow_none=True)
    author_email = String(required=False, allow_none=True)
    maintainer = String(required=False, allow_none=True)
    maintainer_email = String(required=False, allow_none=True)
    url = String(
        required=False, validate=Length(0, 200), allow_none=True
    )  # Note: making this a URL would force checks that might fail
    private = Boolean(
        required=False, load_default=False
    )  # By default, dataset metadata will be publicly available

    version = String(required=False, validate=Length(0, 100), allow_none=True)


class GroupSchema(Schema):
    name = NameID()

    state = String(required=False, validate=OneOf(["draft", "active", "deleted"]))

    title = String(required=False)
    description = String(required=False)
    image_url = String(required=False)
    # type = String(required=False, validate=OneOf(["group", "organization"]))
    approval_status = String(
        required=False,
        validate=OneOf(["approved", "pending", "rejected"]),
    )

    # It seems that Groups and Organizations do not support tags, and furthermore,
    # the CKAN decision was to drop them altogether from groups and organizations
    #
    # https://github.com/ckan/ckan/issues/4388
    #
    # tags = List(String, required=False)

    extras = Dict(required=False)


class OrganizationSchema(GroupSchema):
    pass


class ResourceCreationRequest(Schema):
    package_id = String(required=True)
    url = String(required=False, allow_none=True)
    format = String(required=False, allow_none=True)
    name = String(required=False, allow_none=True)
    description = String(required=False, allow_none=True)
    resource_type = String(
        required=False, validate=OneOf(["file", "api", "service"]), allow_none=True
    )
    hash = String(required=False, allow_none=True)
    size = Integer(required=False, allow_none=True)
    extra = Dict(required=False, allow_none=True)
    mimetype = String(required=False, allow_none=True)
    mimetype_inner = String(required=False, allow_none=True)
    cache_url = String(required=False, allow_none=True)
    cache_last_updated = DateTime(required=False, allow_none=True)

    class Meta:
        unknown = INCLUDE


class ResourceUpdateRequest(ResourceCreationRequest):
    class Meta:
        partial = True
        unknown = INCLUDE


class VocabularyCreationRequest(EntityCreationRequest):
    name = NameID()
    tags = List(String, required=True)


class VocabularyUpdateRequest(VocabularyCreationRequest):
    tags = List(String, required=True)

    class Meta:
        exclude = ["name"]


class TagCreationRequest(EntityCreationRequest):
    name = NameID()
    vocabulary_id = String(required=True)


class FacetSearchSpec(Schema):
    fields = List(String, required=True)
    mincount = Integer(required=False)
    limit = Integer(required=False)


class EntitySearchQuery(PaginationParameters):
    q = String(required=False)
    bbox = List(
        Float,
        required=False,
        validate=[Length(4)],
        allow_none=True,
    )
    fq = List(String, required=False)
    fl = List(
        String,
        required=False,
        allow_none=True,
        load_default=None,
    )
    sort = String(required=False)
    facet = Nested(FacetSearchSpec, required=False)
    include_private = Boolean(
        required=False,
        load_default=False,
        metadata={
            "description": "Include private datasets in the search results.",
        },
    )


class ResourceSearchQuery(PaginationParameters):
    query = List(String)
    order_by = String(required=False)


class RegistryCredentials(Schema):
    title = String(required=True)


# =============================================
#
#  Older non-generic schema definitions
#
# =============================================


def validate_status(value):
    """Custom validator to ensure status is either a string or an integer"""
    if not isinstance(value, (str, int)):
        raise ValidationError("Status must be either a string or an integer.")


class ResponseOK(Schema):
    help = URL(required=True)
    result = Dict(required=True)
    success = Boolean(required=True)


class ResponseError(Schema):
    help = URL(required=True)
    error = Dict(required=True)
    success = Boolean(required=True)


class ResponseAmbiguous(Schema):
    help = fields.URL(required=True)
    success = fields.Boolean(required=True)

    # Use fields that are conditionally required depending on success
    result = fields.Dict(required=False)
    error = fields.Dict(required=False)

    class Meta:
        unknown = (
            INCLUDE  # This allows extra fields not explicitly defined in the schema
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, data):
        """
        Custom validation to ensure either 'result' or 'error' is present
        based on the 'success' value.
        """
        if data.get("success"):
            if "result" not in data:
                raise ValueError("'result' field is required when success is True.")
        else:
            if "error" not in data:
                raise ValueError("'error' field is required when success is False.")
        return data


class Identifier(Schema):
    id = String(
        required=False,
        validate=Length(0, 64),
        metadata={
            "example": "6dc36257-abb6-45b5-b3bb-5f94160fc2ee",
        },
    )


class RolesInput(Schema):
    roles = List(String, required=True)


class NewUser(Schema):
    username = String(required=True, validate=Length(0, 25))
    email = String(required=True, validate=Length(0, 125))
    first_name = String(required=True, validate=Length(0, 100))
    last_name = String(required=True, validate=Length(0, 100))
    password = String(required=True, validate=Length(8, 25))
    enabled = Boolean(required=True)
    email_verified = Boolean(required=True)


class ActivationInput(Schema):
    id = String(required=True, validate=Length(0, 50))


class UpdatedUser(Schema):
    email = String(required=False, validate=Length(0, 125))
    first_name = String(required=False, validate=Length(0, 100))
    last_name = String(required=False, validate=Length(0, 100))
    enabled = Boolean(required=False)
    email_verified = Boolean(required=False)


class UserRole(Schema):
    id = String(required=True, validate=Length(0, 50))
    username = String(required=True, validate=Length(0, 50))
    role = String(required=True, validate=OneOf(["admin", "editor", "member"]))


class NewToken(Schema):
    username = String(required=True, validate=Length(0, 50))
    password = String(required=True, validate=Length(0, 50))


class ImpersonateToken(Schema):
    username = String(required=True, validate=Length(0, 50))


class RefreshToken(Schema):
    refresh_token = String(required=True)


# class Tag(Schema):
#    name = String(required=True)


class BasicMetadata(Schema):
    title = String(required=True, validate=Length(0, 200))
    notes = String(required=True, validate=Length(0, 10000))
    url = URL(required=False)
    tags = List(String, required=True)
    private = Boolean(
        required=False, load_default=False
    )  # By default, dataset metadata will be publicly available
    extra = Dict(
        required=False
    )  # Any other user-specified basic metadata must conform with CKAN

    @pre_load
    def unwrap_envelope(self, data, **kwargs):
        extra = {}
        rest = {}
        for k, v in data.items():
            if k in optional_basic_metadata:
                extra[k] = v
            else:
                rest[k] = v
        return {"extra": extra, **rest}


class ExtraMetadata(Schema):
    spatial = String(required=False, validate=Length(0, 10000))  # spatial extent
    spatial_resolution_in_meters = String(
        required=False, validate=Length(0, 200)
    )  # spatial resolution
    temporal_start = DateTime(
        required=False, validate=Length(0, 30)
    )  # start of temporal extent
    temporal_end = DateTime(
        required=False, validate=Length(0, 30)
    )  # end of temporal extent
    frequency = String(required=False, validate=Length(0, 200))  # temporal resolution
    theme = List(String, required=False)
    language = List(String, required=False)
    documentation = String(required=False, validate=Length(0, 10000))
    extra = Dict(
        required=False
    )  # Any other user-specified metadata will be accepted as extras

    @pre_load
    def unwrap_envelope(self, data, **kwargs):
        extra = {}
        rest = {}
        for k, v in data.items():
            extra[k] = v
        return {"extra": extra, **rest}


class Profile(Schema):
    profile_metadata = Dict(required=True)


class Dataset(Schema):
    basic_metadata = Nested(BasicMetadata, required=True)
    extra_metadata = Nested(ExtraMetadata, required=False)
    profile_metadata = Dict(required=False)


class Artifact(Schema):
    package_metadata = Dict(required=True)
    artifact_metadata = Dict(required=True)


class Track(Schema):
    tracking_metadata = Dict(required=True)


class Package(Schema):
    package_metadata = Dict(required=True)


class Workflow(Schema):
    workflow_metadata = Dict(required=True)
    workflow = Dict(required=False)


class WorkflowProcess(Schema):
    tags = Dict(required=False)
    package_id = String(required=True)


class WorkflowState(Schema):
    state = String(required=True, validate=OneOf(["running", "failed", "succeeded"]))


class Resource(Schema):
    resource_metadata = Dict(required=True)


class Query(Schema):
    q = Dict(required=True)


class Filter(Schema):
    q = String(required=False, metadata={"example": "format:JSON"})  # query search


class ComplexFilter(Schema):
    q = String(
        required=False, metadata={"example": "Topic:*Hydrography*&ext_bbox=20,35,30,42"}
    )  # query search
    ext_bbox = String(
        required=False, metadata={"example": "20,35,30,42"}
    )  # spatial search only
    fq = String(
        required=False, metadata={"example": "organization:athenarc"}
    )  # facet search only


class Ranking(Schema):
    ids = List(String, required=False)
    keywords = List(String, required=False)
    filter_preferences = Dict(required=False)
    rank_preferences = Dict(required=False)
    settings = Dict(required=False)


#    top_k = Integer(required=False, load_default=10)


# class TrackingTags(Schema):
#     dag_id = String(required=True)
#     run_id = String(required=True)
#     task_id = String(required=True)

# class TrackingSettings(Schema):
#     experiment = String(required=True)
#     tags = Nested(TrackingTags, required=True)

# class Tracking(Schema):
#     input = List(String, required=True)
#     output = List(String, required=True)
#     parameters = Dict(required=True)
#     metrics = Dict(required=True)
#     settings = Nested(TrackingSettings, required=True)


class Task_Input(Schema):
    workflow_exec_id = String(required=True)
    docker_image = String(required=True)
    input = List(String, required=True)
    parameters = Dict(required=True)
    package_id = String(required=True)
    tags = Dict()


# class Task_Input_v2(Schema):
#     workflow_exec_id = String(required = True)
#     tool_name = String(required = False)
#     docker_image = String(required = False)
#     inputs = Dict(keys=String(),values=List(String),required=False)
#     parameters = Dict(required = True)
#     datasets = Dict(keys=String(),values=String())


class StringOrDictField(fields.Field):
    def _deserialize(self, value, attr, data, **kwargs):
        if isinstance(value, str):
            return value
        elif isinstance(value, dict):
            return value
        raise ValidationError("Field must be either a string or a dictionary.")


class Task_Input_v2(Schema):
    workflow_exec_id = fields.String(required=True)
    tool_name = fields.String(required=False)
    docker_image = fields.String(required=False)
    inputs = Dict(keys=fields.String(), values=fields.List(String), required=False)
    outputs = Dict(keys=fields.String(), required=False)
    secrets = Dict(required=False)
    datasets = fields.Dict(
        keys=fields.String(), values=StringOrDictField(), required=False
    )
    parameters = fields.Dict(required=True)
    tags = fields.Dict()


class Task_Output(Schema):
    metrics = Dict(required=False)
    status = fields.Raw(
        required=True, validate=validate_status
    )  # Accepts both str and int
    error = String(required=False)
    message = String(required=False)
    output = Dict(keys=fields.String(), values=fields.String(), required=False)
    outputs = Dict(keys=fields.String(), values=fields.String(), required=False)


class TaskListQuery(Schema):
    state = String(
        required=False, validate=OneOf(["running", "failed", "succeeded", "created"])
    )
    limit = Integer(required=False, validate=Range(min=0))
    offset = Integer(required=False, validate=Range(min=0))


class Workflow_Input(Schema):
    # workflow_id = String(required = True)
    tags = Dict()


class Workflow_Commit(Schema):
    workflow_exec_id = String(required=True)
    state = String(required=True)


class Workflow_Statistics(Schema):
    workflow_tags = List(String, required=True)
    parameters = List(String, required=True)
    metrics = List(String, required=True)


# NOT USED EXAMPLES

artifact_examples = {
    "Create new package for artifact": {
        "package_metadata": {
            "title": "Results of Airflow dag mycalc",
            "tags": [{"name": "Artifact"}, {"name": "Workflow"}],
            "extras": [
                {"key": "dag_id", "value": "mycalc"},
                {"key": "run_id", "value": "scheduled__2023-07-11T00:00:00+00:00"},
            ],
            "notes": "My calculation using AirFlow",
        },
        "artifact_metadata": {
            "url": "s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv",
            "run_uuid": "d63a2b507bf6b6eadcb2c8de378c0370",
            "name": "Results of deduplication task",
            "description": "This is the test artifact uploaded to minio S3 in CSV format",
            "format": "CSV",
            "resource_tags": ["Artifact", "MLFlow"],
        },
    },
    "Associate artifact to existing package": {
        "package_metadata": {"package_id": "test_klms_api_46"},
        "artifact_metadata": {
            "url": "s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv",
            "run_uuid": "d63a2b507bf6b6eadcb2c8de378c0370",
            "name": "Results of deduplication task",
            "description": "This is the test artifact uploaded to minio S3 in CSV format",
            "format": "CSV",
            "resource_tags": ["Artifact", "MLFlow"],
        },
    },
}

tracking_examples = {
    "track_on_a_new_package": {
        "params": {
            "experiment": "Downloading_GDELT_Demo_download",
            "log": {},
            "title": "Workflow for Downloading_GDELT_Demo 20230713",
            "path": "s3://gdelt-bucket/download_gdelt_20230713.csv",
        },
        "settings": {
            "dag_id": "Downloading_GDELT_Demo",
            "run_id": "scheduled__2023-07-13T00:00:00+00:00",
            "user": "azeakis",
        },
    },
    "track_on_existing_package": {
        "params": {
            "experiment": "Downloading_GDELT_Demo_deduplicate",
            "package_id": "4599173f-b3ef-4d82-b0ff-6af0c069e450",
            "log": {},
            "path": "s3://gdelt-bucket/deduplicate_gdelt_20230713.csv",
        },
        "settings": {
            "dag_id": "Downloading_GDELT_Demo",
            "run_id": "scheduled__2023-07-13T00:00:00+00:00",
            "user": "azeakis",
        },
    },
}
