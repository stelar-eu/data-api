import json

from apiflask import Schema, abort
from apiflask.fields import Boolean, Integer, String, Dict, Nested, URL
from apiflask.validators import Length, OneOf, NoneOf


class ResponseOK(Schema):
    help = URL(required=True)
    result = Dict(required=True)
    success = Boolean(required=True)


class ResponseError(Schema):
    help = URL(required=True)
    error = Dict(required=True)
    success = Boolean(required=True)


class Identifier(Schema):
    id = String(required=False, validate=Length(0, 50), example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")


class NewUser(Schema):
    name = String(required=True, validate=Length(0, 20))
    password = String(required=True, validate=Length(0, 20))
    email = String(required=True, validate=Length(0, 50))
    fullname = String(required=True, validate=Length(0, 100))
    about = String(required=False, validate=Length(0, 200))
    image_url = String(required=False, validate=Length(0, 200))


class ChangedUser(Schema):
    id = String(required=True, validate=Length(0, 50))
    name = String(required=False, validate=Length(0, 20))
    password = String(required=False, validate=Length(0, 20))
    email = String(required=False, validate=Length(0, 50))
    fullname = String(required=False, validate=Length(0, 100))
    about = String(required=False, validate=Length(0, 200))
    image_url = String(required=False, validate=Length(0, 200))


class UserRole(Schema):
    id = String(required=True, validate=Length(0, 50))
    username = String(required=True, validate=Length(0, 50))
    role = String(required=True, validate=OneOf(['admin', 'editor', 'member']))


class NewToken(Schema):
    user = String(required=True, validate=Length(0, 50))
    name = String(required=True, validate=Length(0, 50))


class Dataset(Schema):
    basic_metadata = Dict(required=True)
    custom_metadata = Dict(required=False)
    profile_metadata = Dict(required=False)


class Artifact(Schema):
    package_metadata = Dict(required=True)
    artifact_metadata = Dict(required=True)


class Package(Schema):
    package_metadata = Dict(required=True)


class Resource(Schema):
    resource_metadata = Dict(required=True)


class Query(Schema):
    q = Dict(required=True)


class Filter(Schema):
    q = String(required=False, example="format:JSON")	# query search


class ComplexFilter(Schema):
    q = String(required=False, example="Topic:*Hydrography*&ext_bbox=20,35,30,42")	# query search
    ext_bbox = String(required=False, example="20,35,30,42")  				# spatial search only
    fq = String(required=False, example="organization:athenarc")        		# facet search only


class TrackingParams(Schema):
    experiment = String(required=True)
    log = Dict(required=True)
    path = String(required=True)
    package_id = String(validate=NoneOf(['']), missing=None)
    title = String(validate=NoneOf(['']), missing=None)


class TrackingSettings(Schema):
    dag_id = String(required=True)
    run_id = String(required=True)
    user = String(required=True)


class Tracking(Schema):
    params = Nested(TrackingParams, required=True)
    settings = Nested(TrackingSettings, required=True)

# class Tracking(Schema):
#     params = Dict(required=True)
#     settings = Dict(required=True)



# NOT USED EXAMPLES

artifact_examples = {
       "Create new package for artifact": {"package_metadata":{"title":"Results of Airflow dag mycalc", "tags":[{"name": "Artifact"}, {"name": "Workflow"}], "extras":[{"key":"dag_id", "value":"mycalc"}, {"key":"run_id", "value":"scheduled__2023-07-11T00:00:00+00:00"}], "notes": "My calculation using AirFlow"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "run_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}}, 
       "Associate artifact to existing package": {"package_metadata":{"package_id": "test_klms_api_46"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "run_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}}
   }

tracking_examples = {
       'track_on_a_new_package': {'params': {'experiment': 'Downloading_GDELT_Demo_download', 'log': {}, 'title': 'Workflow for Downloading_GDELT_Demo 20230713', 'path': 's3://gdelt-bucket/download_gdelt_20230713.csv'}, 'settings': {'dag_id': 'Downloading_GDELT_Demo', 'run_id': 'scheduled__2023-07-13T00:00:00+00:00', 'user': 'azeakis'}},
       'track_on_existing_package': {'params': {'experiment': 'Downloading_GDELT_Demo_deduplicate', 'package_id': '4599173f-b3ef-4d82-b0ff-6af0c069e450', 'log': {}, 'path': 's3://gdelt-bucket/deduplicate_gdelt_20230713.csv'}, 'settings': {'dag_id': 'Downloading_GDELT_Demo', 'run_id': 'scheduled__2023-07-13T00:00:00+00:00', 'user': 'azeakis'}}
   }
