# flake8: noqa: E402
#
# We need to configure logging as the first thing to do...
#
import logging

import authz_module
import logsys

logsys.configure()

import json
import os
import re
import uuid
from datetime import date
from datetime import datetime as datetime
from urllib.parse import urljoin, urlparse, urlunparse

import pandas as pd
import psycopg2
import requests
import yaml
from apiflask import APIFlask
from flask import current_app, g, jsonify, redirect, request, url_for
from flask.json.provider import DefaultJSONProvider

# for keycloak integration with the api
from psycopg2.extras import RealDictCursor

import execution
import kutils

# Input schemata for validating several API requests
import schema
import sql_utils

# Auxiliary custom functions & SQL query templates for ranking
import utils
from auth import security_doc, token_active
from backend.ckan import initialize_ckan_client
from backend.pgsql import get_mdb_pool, initialize_mdb_pool

# Import demo token creator
from demo_t import get_demo_ckan_token
from routes.admin import admin_bp
from routes.auth_tool import auth_tool_bp
from routes.catalog import catalog_bp
from routes.dashboard import dashboard_bp
from routes.publisher import publisher_bp
from routes.settings import settings_bp
from routes.users import api_user_editor, users_bp
from routes.workflows import workflows_bp

# fmt: on


# from container_utils import create_container

logger = logging.getLogger(__name__)

app = APIFlask(__name__, spec_path="/specs", docs_path="/docs")
app.secret_key = os.getenv("SESSION_SECRET_KEY", "None")
app.config.from_prefixed_env()


# ------------------ Error Processor ------------------------

app.config["VALIDATION_ERROR_SCHEMA"] = schema.APIErrorResponse
app.config["HTTP_ERROR_SCHEMA"] = schema.APIErrorResponse


@app.error_processor
def global_error_processor(error):
    return {
        "help": request.url,
        "success": False,
        "error": {
            "__type": error.__class__.__name__,
            "status_code": error.status_code,
            "message": error.message,
            "detail": error.detail,
        },
    }, error.status_code


# ################# BLUEPRINT REGISTRATION ##################

# Blueprints are used to split the API into logical parts,
# such as User Management, Catalog Management,
# Workflow/Execution management etc.

app.register_blueprint(users_bp, url_prefix="/api/v1/users")
app.register_blueprint(dashboard_bp, url_prefix="/console/v1")
app.register_blueprint(publisher_bp, url_prefix="/console/v1/publisher")
app.register_blueprint(settings_bp, url_prefix="/console/v1/settings")
app.register_blueprint(admin_bp, url_prefix="/console/v1/admin")
app.register_blueprint(auth_tool_bp, url_prefix="/api/v1/auth")
app.register_blueprint(catalog_bp, url_prefix="/api/v2")
app.register_blueprint(workflows_bp, url_prefix="/api/v2")

logger.info("Blueprints registered successfully.")
logger.debug("Endpoints: %s", app.url_map)


############################################################


######### JINJA ENV FILTERS ###########
def format_datetime(value):
    if value:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f").strftime(
            "%d/%m/%Y %H:%M"
        )
    return "N/A"


app.jinja_env.filters["format_datetime"] = format_datetime
#######################################


# Custom class to retain original ISO format like 'yyyy-mm-dd hh:mm:ss.m' in date/time/timestamp values
class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, date | datetime):
            return obj.isoformat()

        # Handle iterators (the old code was attempting to
        # handle iterables, but this makes no sense!!
        # It would apply to strings, lists, tuples, dicts, etc.)
        if hasattr(obj, "__next__"):
            return list(obj)

        return super().default(obj)


app.json = CustomJSONProvider(app)


# -----------------
# Entry point
# -----------------


@app.route("/", methods=["GET"])
@app.doc(tags=["KLMS Data API"])
def home():
    """Entry point to the Console of Knowledge Lake Management System."""
    return redirect(url_for("dashboard_blueprint.login"))


@app.route("/help", methods=["GET"])
@app.output(schema.ResponseOK, status_code=200)
@app.doc(responses=[404], tags=["KLMS Data API"])
def help():
    """Entry point to the Data API of Knowledge Lake Management System.

    Args:

    Returns:
        A JSON with basic information about the API.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/
    settings = app.config["settings"]
    extra_help = {
        sname: settings[s]
        for s, sname in [
            ("MINIO_API_EXT_URL", "s3_api"),
            ("KEYCLOAK_ISSUER_URL", "keycloak_issuer_url"),
            ("KEYCLOAK_REALM", "keycloak_realm"),
            ("KEYCLOAK_EXT_URL", "keycloak_url"),
            ("KLMS_DOMAIN_NAME", "klms_dns_domain"),
            ("MINIO_CONSOLE_URL", "minio_console_url"),
            ("MAIN_EXT_URL", "klms_root_url"),
        ]
        if s in settings
    }

    response = {
        "help": request.base_url,
        "success": True,
        "result": {
            "message": "Data API for managing resources in STELAR Knowledge Lake Management System.",
            "OpenAPI specifications": request.root_url + "specs",
            "Swagger UI": request.root_url + "docs",
            "Console": request.root_url + "console/v1/",
        }
        | extra_help,
    }

    return jsonify(response)


################################## SEARCH OPERATIONS ########################################


@app.route("/api/v1/dataset/export_zenodo", methods=["GET"])
@app.input(
    schema.Identifier, location="query", example="cf0c3c59-fc41-48c9-a529-6b9feff42991"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_export_zenodo_dataset_id(query_data):
    """Export all metadata available for a dataset (i.e., CKAN package) in order to published to Zenodo.

    Args:
        id: The unique identifier of the dataset as listed in CKAN.

    Returns:
        A JSON with metadata compliant with DataCite's Metadata Schema employed by Zenodo.
    """

    config = current_app.config["settings"]

    # Check if an ID (name) for a dataset was provided as argument
    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?id=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No identifier provided. Please specify the id of the requested dataset."
                ],
            },
        }
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(
        config["CKAN_API"] + "package_show?id=" + id
    )  # , headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))
    resp_json = response.json()

    zenodo_metadata = {}
    if resp_json["success"]:
        dataset = resp_json["result"]
        creator_id = dataset["creator_user_id"]

        # Make another GET request to the CKAN API to get details about the creator of the CKAN package
        # IMPORTANT! CKAN requires NO authentication for GET requests
        resp_creator = requests.get(
            config["CKAN_API"] + "user_show?id=" + creator_id
        )  # , headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))
        json_creator = resp_creator.json()

        # Internal call to find the organization where the creator of the dataset belongs to
        #        resp_org = requests.get(api_user_organization, params = {'id':creator_id})
        #        params = {'id':creator_id}
        #        resp_org = redirect(url_for('api_user_organization', query_data=creator_id))

        # Make a GET request to the CKAN API to find the organization where the creator of the dataset belongs to
        # IMPORTANT! CKAN requires NO authentication for GET requests
        resp_org = requests.get(
            config["CKAN_API"] + "organization_list_for_user?id=" + creator_id
        )  # , headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))
        json_org = resp_org.json()

        if json_org["success"]:
            # Formulate metadata according to Zenodo specifications; no DOI specified
            zenodo_metadata = utils.prepareZenodoMetadata(
                dataset,
                json_creator["result"]["display_name"],
                json_org["result"][0]["title"],
                None,
            )

    return jsonify(zenodo_metadata)


@app.route("/api/v1/catalog/search", methods=["POST"])
@app.input(
    schema.Query,
    location="json",
    example={
        "q": {
            "Topic": "POI",
            "INSPIRE theme": "Location",
            "spatial": {
                "type": "Polygon",
                "coordinates": [
                    [
                        [12.362, 45.39],
                        [12.485, 45.39],
                        [12.485, 45.576],
                        [12.362, 45.576],
                        [12.362, 45.39],
                    ]
                ],
            },
        }
    },
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_catalog_search(json_data):
    """Submit a search request to the Data Catalog.

    Args:
        json_data: A JSON with filtering criteria for searching in the Data Catalog. Keys should match properties specified in the STELAR Ontology.

    Returns:
        A JSON with all metadata available in the Catalog for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/search -d '{"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}}'

    config = current_app.config["settings"]

    if request.headers:
        if request.headers:
            package_headers, resource_headers = utils.create_CKAN_headers(
                get_demo_ckan_token()
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    if request.data:
        filter = request.data
        specs = json.loads(filter.decode("utf-8"))
        if "q" in specs:
            q = utils.format_CKAN_filter(specs["q"])
        #            print(q)
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Incorrect specifications",
                    "name": [
                        "Incorrect or no filters provided to search in the Data Catalog. Please specify at least one filtering criterion in a dictionary."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No filters provided to search in the Data Catalog. Please specify at least one filtering criterion in a dictionary."
                ],
            },
        }
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! Although CKAN generally requires NO authentication for GET requests, it is important in order to also retrieve private datasets of the user's organization
    response = requests.get(
        config["CKAN_API"] + "package_search" + q + "&include_private=True&fl=*,score",
        headers=package_headers,
    )

    return response.json()


@app.route("/api/v1/dataset/search", methods=["GET"])
@app.input(
    schema.ComplexFilter, location="query", example="q=Lakes&ext_bbox=20,35,30,42"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_package_search(query_data):
    """Submit a search request against CKAN packages (datasets).

    Args:
        q: Filtering criteria for searching in CKAN. Search may concern either metadata values (?q=) or facets (?fc=) or spatial extents (?ext_bbox=) only. One argument (?q= or ?fq= or ?ext_bbox) must be specified per request. Syntax must follow <a href="https://docs.ckan.org/en/latest/api/#ckan.logic.action.get.package_search">SOLR specifications for filtering</a>.

    Returns:
        A JSON with all metadata available in CKAN for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/dataset/search?q=Topic:*POI*
    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/dataset/search?fq=organization:athenarc
    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/dataset/search?q=Lakes&ext_bbox=20,35,30,42

    config = current_app.config["settings"]

    #    if request.headers:
    #        if request.headers.get('Api-Token') is not None:
    #            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
    #        else:
    #            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
    #            return jsonify(response)
    #    else:
    #        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
    #        return jsonify(response)

    # Multiple criteria can be correctly passed with argument ?q
    if "q" in query_data:  # Search on various metadata
        q = "?q=" + query_data["q"]
    elif "ext_bbox" in query_data:  # Search on spatial extent only
        q = "?ext_bbox=" + query_data["ext_bbox"]
    elif "fq" in query_data:  # Search on facets only
        q = "?fq=" + query_data["fq"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No filtering criteria provided to search for datasets in the Catalog. Please specify at least one filter as argument."
                ],
            },
        }
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! Although CKAN generally requires NO authentication for GET requests, it is important in order to also retrieve private datasets of the user's organization
    # IMPORTANT! To return all available results, must specify the max number of rows
    response = requests.get(
        config["CKAN_API"]
        + "package_search"
        + q
        + "&include_private=True&fl=*,score&rows="
        + str(config["RANK_MAX_TOPK"])
        + "&start=0"
    )  # , headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    # Pass an empty data frame to report the original SOLR scores; no facet specs need be added; no profiling attributes involved
    return utils.assign_scores(response, pd.DataFrame(), {}, {}, [])


@app.route("/api/v1/resource/search", methods=["GET"])
@app.input(schema.Filter, location="query", example="q=format:JSON")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_resource_search(query_data):
    """Submit a request to search among the CKAN resources accessible by the user.

    Args:
        q: Filtering criteria for searching in CKAN. Syntax must follow SOLR specifications for filtering. https://docs.ckan.org/en/latest/api/#ckan.logic.action.get.resource_search

    Returns:
        A JSON with all metadata available in CKAN for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource/search?q=format:JSON

    config = current_app.config["settings"]

    if request.headers:
        if request.headers:
            package_headers, resource_headers = utils.create_CKAN_headers(
                get_demo_ckan_token()
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    # Check if filtering criteria was provided as argument
    if "q" in query_data:
        q = query_data["q"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No filtering criteria provided to search for resources in the Catalog. Please specify at least one filter as argument."
                ],
            },
        }
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.post(
        config["CKAN_API"] + "resource_search?query=" + q, headers=package_headers
    )

    return response.json()


@app.route("/api/v1/resource/profile", methods=["GET"])
@app.input(
    schema.Identifier, location="query", example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_resource_profile(query_data):
    """Get the JSON profile available for a resource that is accessible by the user.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON object with all profiling information as maintained in CKAN for the specified resource.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource/download?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

    config = current_app.config["settings"]

    if request.headers:
        if request.headers.get("Api-Token") is not None:
            package_headers, resource_headers = utils.create_CKAN_headers(
                request.headers["Api-Token"]
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, "
                    "including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    # Check if an ID (name) for a resource was provided as argument
    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?id=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No identifier provided. Please specify the id of the requested resource."
                ],
            },
        }
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(
        config["CKAN_API"] + "resource_show?id=" + id, headers=resource_headers
    )  # auth=HTTPBasicAuth(config.username, config.password))

    if response.status_code == 200:
        json_response = response.json()
        if json_response["success"]:
            #        # IMPORTANT: If a firewall existing on the API server, the file cannot be downloaded from CKAN
            #            url_profile = json_response['result']['url']
            #            print(url_profile)
            #            with urllib.request.urlopen(url_profile) as url:
            #                print(url)
            #                data = json.load(url)
            #                return data
            # ALTERNATIVE: Get the original path to the file when uploaded to CKAN
            path_profile = json_response["result"]["file"]
            print(path_profile)
            with open(path_profile) as json_file:
                data = json.load(json_file)
                return jsonify(data)

    return None


@app.route("/api/v1/workflow/input/dataset", methods=["GET"])
@app.input(
    schema.Identifier,
    location="query",
    example="id=82aaa2df-be92-46ee-a36b-cc59122a5d5b",
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_workflow_input_dataset(query_data):
    """Submit a request to identify in which workflow(s) a dataset (CKAN package) has been given as input to any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the dataset by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this dataset has been given as input.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/input/dataset?id=82aaa2df-be92-46ee-a36b-cc59122a5d5b

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No dataset identifier provided to search in the Catalog. Please specify a valid identifier for the dataset."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("workflow_input_dataset_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/workflow/output/dataset", methods=["GET"])
@app.input(
    schema.Identifier,
    location="query",
    example="id=9232eef6-5acf-4280-b3e9-38d6c8935d7d",
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_workflow_output_dataset(query_data):
    """Submit a request to identify in which workflow(s) the given dataset (CKAN package) has been issued as output in any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the dataset by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this dataset has been issued as output.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/output/dataset?id=9232eef6-5acf-4280-b3e9-38d6c8935d7d

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No dataset identifier provided to search in the Catalog. Please specify a valid identifier for the dataset."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("workflow_output_dataset_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/workflow/input/resource", methods=["GET"])
@app.input(
    schema.Identifier,
    location="query",
    example="id=6b077882-bd24-480b-896b-d7e8431338e5",
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_workflow_input_resource(query_data):
    """Submit a request to identify in which workflow(s) a file (CKAN resource) has been given as input to any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the resource by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this file has been given as input.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/input/resource?id=6b077882-bd24-480b-896b-d7e8431338e5

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No resource identifier provided to search in the Catalog. Please specify a valid identifier for the resource."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("workflow_input_resource_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/workflow/output/resource", methods=["GET"])
@app.input(
    schema.Identifier,
    location="query",
    example="id=50156c05-6150-494d-b372-77d859f768d2",
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_workflow_output_resource(query_data):
    """Submit a request to identify in which workflow(s) the given file (CKAN resource) has been issued as output in any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the resource by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this file has been issued as output.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/output/resource?id=50156c05-6150-494d-b372-77d859f768d2

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No resource identifier provided to search in the Catalog. Please specify a valid identifier for the resource."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("workflow_output_resource_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/task/execution/input", methods=["GET"])
@app.input(
    schema.Identifier, location="query", example="id=0075f24c7b654246a65c12739e96b867"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_task_execution_input(query_data):
    """Submit a request to the Knowledge Graph to retrieve the identifiers of dataset(s) given as input to the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the list of dataset identifiers (CKAN resources) collected in MLFlow for the specified task execution.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/input?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_input_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/task/execution/output", methods=["GET"])
@app.input(
    schema.Identifier, location="query", example="id=0075f24c7b654246a65c12739e96b867"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_task_execution_output(query_data):
    """Submit a request to the Knowledge Graph to retrieve the identifiers of dataset(s) issued as output from the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the list of dataset identifiers (CKAN resources) collected as output in MLFlow for the specified task execution.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/output?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_output_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/task/execution/metrics", methods=["GET"])
@app.input(
    schema.Identifier, location="query", example="id=0075f24c7b654246a65c12739e96b867"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_task_metrics(query_data):
    """Submit a request to the Knowledge Graph retrieve the metrics issued for the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the metrics collected in MLFlow for the specified task execution.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/metrics?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_metrics_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/task/execution/parameters", methods=["GET"])
@app.input(
    schema.Identifier, location="query", example="id=0075f24c7b654246a65c12739e96b867"
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"])
def api_task_parameters(query_data):
    """Submit a request to the Knowledge Graph retrieve the parameters specified for the task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the parameters specified in MLFlow for the specified task execution.
    """

    # EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/parameters?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config["settings"]

    if "id" in query_data:
        id = query_data["id"]
    else:
        response = {
            "success": False,
            "help": request.url + "?q=",
            "error": {
                "__type": "No specifications",
                "name": [
                    "No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_parameters_template", id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return jsonify(json.loads(response.text))


@app.route("/api/v1/graph/search", methods=["POST"])
@app.input(
    schema.Filter,
    location="json",
    example={
        "q": "PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"
    },
)
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Search Operations"], security=security_doc)
@token_active
def api_sparql(json_data):
    """Submit a search request to the SPARQL endpoint.

    Args:
        json_data: A JSON specifying the SELECT query in SPARQL for searching the Knowledge Graph via Ontop. Syntax must follow SPARQL specifications for Ontop.

    Returns:
        A JSON with all RDF triples qualifying to the search criteria.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/text' http://127.0.0.1:9055/api/v1/graph/search -d '{"q":"PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"}'

    config = current_app.config["settings"]

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        if "q" in specs:
            sparql = specs["q"]
            print(sparql)
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Incorrect specifications",
                    "name": [
                        "Incorrect or no filters provided to search in the Data Catalog. Please specify a valid SPARQL query command."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No SPARQL query provided to search in the Knowledge Graph. Please specify a valid SPARQL query command."
                ],
            },
        }
        return jsonify(response)

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }

    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    return response.json()


# !!!!!!!
# THE FOLLOWING ENDPOINTS ARE SUCCEPTIBLE TO SQL INJECTION ATTACKS


# @app.route("/api/v1/catalog/sql", methods=["POST"])
# @app.input(
#    schema.Filter,
#    location="json",
#    example={"q": "SELECT * FROM public.package LIMIT 5"},
# )
# @app.output(schema.ResponseOK, status_code=200)
# @app.doc(tags=["Search Operations"], security=security_doc)
# @token_active
def api_sql(json_data):
    """Submit a SELECT SQL command to the PostgreSQL database.

    Args:
        json_data: A JSON specifying the SELECT query in SQL for searching the Data Catalog in PostgreSQL. Syntax must follow SQL specifications for PostgreSQL.

    Returns:
        A JSON with all results qualifying to the search criteria.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/text' http://127.0.0.1:9055/api/v1/catalog/sql -d '{"q":"SELECT * FROM public.package LIMIT 5"}'

    config = current_app.config["settings"]

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        if "q" in specs:
            sql = specs["q"]
        #            print(sql)
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Incorrect specifications",
                    "name": [
                        "Incorrect or no filters provided to search in the Data Catalog. Please specify a valid SELECT query command in SQL."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No SQL query provided to search in the Data Catalog. Please specify a valid SELECT query command in SQL."
                ],
            },
        }
        return jsonify(response)

    # sql_headers = {'Content-Type':'application/sql-query', 'Accept':'application/json'}

    conn = psycopg2.connect(
        dbname=config["dbname"],
        user=config["dbuser"],
        password=config["dbpass"],
        host=config["dbhost"],
        port=config["dbport"],
    )  # , sslmode=config['sslmode'])

    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(sql)
    results = cur.fetchall()
    conn.commit()

    return jsonify(results)


# @app.route("/api/v1/catalog/facet/values", methods=["POST"])
# @app.input(schema.Filter, location="json", example={"q": "format"})
# @app.output(schema.ResponseOK, status_code=200)
# @app.doc(tags=["Search Operations"], security=security_doc)
# @token_active
def api_facet_values(json_data):
    """Submit a SELECT SQL command to the PostgreSQL database.

    Args:
        json_data: A JSON specifying the facet name (corresponding to an SQL view or table) to query in the PostgreSQL database of the Data Catalog.

    Returns:
        A JSON with all values available for the specified facet.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/text' http://127.0.0.1:9055/api/v1/catalog/facet/values -d '{"q":"format"}'

    config = current_app.config["settings"]

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        # Identify the SQL view that corresponds to the specified facet
        if "q" in specs and utils.sql_views.get(specs["q"]):
            view_name = str(utils.sql_views.get(specs["q"]))
            sql = "SELECT * FROM " + view_name
        #            print(sql)
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Incorrect specifications",
                    "name": [
                        "Incorrect or no filters provided to fetch facet values from the Data Catalog. Please specify a valid name for SQL view."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No valid facet specified to fetch its values from the Data Catalog. Please specify a valid name for SQL view."
                ],
            },
        }
        return jsonify(response)

    # Execute the SQL view to fetch the values
    # sql_headers = {'Content-Type':'application/sql-query', 'Accept':'application/json'}
    conn = psycopg2.connect(
        dbname=config["dbname"],
        user=config["dbuser"],
        password=config["dbpass"],
        host=config["dbhost"],
        port=config["dbport"],
    )  # , sslmode=config['sslmode'])
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(sql)
    results = cur.fetchall()
    conn.commit()

    # Exclude identifiers from the returned results
    for res in results:
        if "id" in res:
            del res["id"]
        elif "package_id" in res:
            del res["package_id"]

    return jsonify(results)


################################## RANKING OPERATIONS ########################################


@app.route("/api/v1/catalog/rank", methods=["POST"])
@app.input(
    schema.Ranking,
    location="json",
    example={
        "rank_preferences": {
            "tags": ["Geospatial", "POI"],
            "theme": ["Land Use", "Land Cover", "Imagery"],
            "language": ["en", "el", "fr"],
            "spatial": {
                "type": "Polygon",
                "coordinates": [
                    [
                        [12.362, 45.39],
                        [12.485, 45.39],
                        [12.485, 45.576],
                        [12.362, 45.576],
                        [12.362, 45.39],
                    ]
                ],
            },
        },
        "settings": {"k": 10, "algorithm": "threshold", "weights": [0.3, 0.5, 0.4]},
    },
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Ranking Operations"], security=security_doc)
@token_active
def api_catalog_rank(json_data):
    """Submit a rank request regarding specific metadata attributes (facets) to the Data Catalog.

    Args:
        json_data: A JSON with facet preferences for searching in the Data Catalog. Facet name should match a property specified in the STELAR Ontology.

    Returns:
        A JSON with datasets ranked by the specified facet(s). The matching score per facet criterion is also listed per returned dataset.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/rank -d '{"q":{"theme":"POI"}}'

    config = current_app.config["settings"]

    if request.headers:
        if request.headers.get("Api-Token") is not None:
            package_headers, resource_headers = utils.create_CKAN_headers(
                request.headers["Api-Token"]
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    sql = ""
    sql_id_filter = ""
    ids = []
    dict_df_facet_scores = (
        {}
    )  # dictionary with the returned input ranked lists per facet (key -> dataframe)
    k = config["RANK_MAX_TOPK"]  # default top-k value (if not user-specified)
    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        actual_profile_attributes = set(specs["filter_preferences"].keys()).union(
            set(specs["rank_preferences"].keys())
        )
        #        print("INITIAL PROFILE ATTRIBUTES", actual_profile_attributes)

        # STAGE #1: text-based keyword search targets SOLR (search engine for CKAN)
        if "keywords" in specs:  # CASE #1(a): new keyword search
            q = "?q=" + ",".join("'{0}'".format(kw) for kw in specs["keywords"])
            #            print(q)
            # Submit a preliminary search request to CKAN to find packages qualifying to the specified keywords
            # Also include private datasets of the user's organization in the results
            resp_basic = requests.get(
                config["CKAN_API"]
                + "package_search"
                + q
                + "&include_private=True&fl=*,score&rows="
                + str(config["RANK_MAX_TOPK"])
                + "&start=0",
                headers=package_headers,
            )
            if resp_basic.status_code == 200:
                json_resp_basic = resp_basic.json()
                # FIXME: Handle large number of returned id's -> not efficient when filtering with SQL
                if json_resp_basic["success"]:  # Results from keyword-based search only
                    results = json_resp_basic["result"]["results"]
                    ids = [res["id"] for res in results if "id" in res]
        #                    print('keyword results:',len(ids))
        elif (
            "ids" in specs
        ):  # CASE #1(b): Identifiers of datasets already qualifying keyword search criteria
            if len(specs["ids"]) > 0:
                ids = specs["ids"]
        if len(ids) > 0:  # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids)
        else:  # No results from filtering, no sense to continue with further filtering
            response = {
                "help": request.url,
                "result": {
                    "count": 0,
                    "facets": {},
                    "results": [],
                    "sort": "score desc, metadata_modified desc",
                },
                "success": True,
            }
            return jsonify(response)

        # STAGE #2: Apply any filtering criteria (NOT participating in the ranking)
        if "filter_preferences" in specs:
            filter_sql_commands = utils.format_facet_preferences(
                specs["filter_preferences"], sql_id_filter, config["RANK_MAX_TOPK"]
            )
            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            for key in filter_sql_commands.keys():
                sql = filter_sql_commands[key]
                results = utils.execSql(sql)
                #                print(len(results), sql)
                filter_ids = [res["id"] for res in results if "id" in res]
                if sql_id_filter == "":  # No keywords specified in search bar
                    ids = filter_ids
                else:  # Keep only matching id's
                    ids = [id for id in ids if id in filter_ids]
        #                print(key, len(ids))
        if len(ids) > 0:  # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids)
        else:  # No results from filtering, no sense to apply ranking
            response = {
                "help": request.url,
                "result": {
                    "count": 0,
                    "facets": {},
                    "results": [],
                    "sort": "score desc, metadata_modified desc",
                },
                "success": True,
            }
            return jsonify(response)

        # STAGE #3: Prepare SQL queries for each of the ranking preferences
        if "rank_preferences" in specs:
            rank_sql_commands = utils.format_facet_preferences(
                specs["rank_preferences"], sql_id_filter, config["RANK_MAX_TOPK"]
            )
            # FIXME: REMOVE IF HANDLED BY THE FRONT-END
            # Examine settings for ranking
            #            if 'settings' in specs:
            #                if not 'algorithm' in specs['settings']: # Apply default algorithm for rank aggregation
            #                    specs['settings']['algorithm'] = config['RANK_AGG_ALGORITHM']
            #                if 'k' in specs['settings']:
            #                    k = specs['settings']['k']
            #                else:
            #                    specs['settings']['k'] = k    # Rank aggregation library requires the total number of items
            #                    print(specs['settings']['k'])
            #            else:  # Specify default values for rank aggregation
            #                specs['settings'] = {}
            #                specs['settings']['algorithm'] = config['RANK_AGG_ALGORITHM']
            #                specs['settings']['k'] = k

            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            input_lists = []
            for key in rank_sql_commands.keys():
                sql = rank_sql_commands[key]
                #                print(key, '->', sql)
                results = utils.execSql(sql)
                #                print("FIELDS", key, len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if id not in [d["id"] for d in results if "id" in d]:
                        results.append({"id": id, "score": 0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)
            #                # In case a 'value' column (concerning PROFILING) is returned in results, remember to include its values in the final results
            #                if 'value' in dict_df_facet_scores[key].columns:
            #                    profile_attributes.append(key)
            #                    print(key)

            # Fetch values for all profiling metadata elements by submitting a SELECT query to the PostgreSQL database for the collected ids
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            actual_profile_attributes = actual_profile_attributes.intersection(
                utils.profile_attributes
            )
            #            print("ACTUAL PROFILE ATTRIBUTES", actual_profile_attributes)
            for key in list(
                actual_profile_attributes
            ):  # list(set(utils.profile_attributes) - set(rank_sql_commands.keys())):
                sql = utils.identifiers_sql_filter_template.replace(
                    "_VIEW", utils.sql_views[key]
                ).replace("_IDS", sql_id_filter)
                #                print(key, '->', sql)
                results = utils.execSql(sql)
                print("PROFILING", key, len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if id not in [d["id"] for d in results if "id" in d]:
                        results.append({"id": id, "score": 0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)

                input_lists.append(dict_df_facet_scores[key])

            # FIXME: REMOVE IF HANDLED BY THE FRONT-END
            agg_scores = (
                pd.DataFrame()
            )  # No aggregated scores, report the original SOLR scores

            # Compute the final ranked list of all items applying the specified rank aggregation method (e.g., threshold)
        #            agg_scores = ranking.combined_ranking(input_lists, specs['settings'])
        #            ids = agg_scores.index.values  # In case no keywords and no filter criteria have been spcified; only rank preferences
        #            print(agg_scores.index.values)
        elif (
            "settings" in specs
        ):  # Settings for rank aggregation assume at least once facet specification
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Incorrect specifications",
                    "name": [
                        "Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary."
                    ],
                },
            }
            return jsonify(response)
        else:  # No ranking to be applied; only search filters
            specs["rank_preferences"] = {}  # Facets for ranking not specified
            agg_scores = (
                pd.DataFrame()
            )  # No aggregated scores, report the original SOLR scores
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary."
                ],
            },
        }
        return jsonify(response)

    # Retrieve from CKAN all metadata for the datasets in the final (aggregated ranked) list
    # Also include private datasets of the user's organization in the results
    q = "?q=" + " OR ".join(["id:" + id for id in ids])
    response = requests.get(
        config["CKAN_API"]
        + "package_search"
        + q
        + "&rows="
        + str(config["RANK_MAX_TOPK"])
        + "&start=0&include_private=True",
        headers=package_headers,
    )

    # Return the final list of results (the top-k ranked ones in case that ranking preferences are specified)
    return utils.assign_scores(
        response,
        agg_scores,
        dict_df_facet_scores,
        specs["rank_preferences"],
        list(actual_profile_attributes),
    )


############################### PUBLISHING OPERATIONS ############################


# @app.route("/api/v1/catalog/publish", methods=["POST"])
# @app.input(
#     schema.Dataset,
#     location="json",
#     example={
#         "basic_metadata": {
#             "title": "Test Data API 1",
#             "notes": "This dataset contains Points of Interest extracted from OpenStreetMap",
#             "tags": ["STELAR", "OpenStreetMap", "Geospatial", "Bavaria"],
#         },
#         "extra_metadata": {
#             "INSPIRE theme": "Imagery",
#             "theme": ["Earth Sciences", "Landuse", "http://eurovoc.europa.eu/4630"],
#             "language": ["ca", "en", "es"],
#             "spatial": {
#                 "type": "Polygon",
#                 "coordinates": [
#                     [
#                         [12.362, 45.39],
#                         [12.485, 45.39],
#                         [12.485, 45.576],
#                         [12.362, 45.576],
#                         [12.362, 45.39],
#                     ]
#                 ],
#             },
#             "temporal_start": "2023-01-31T11:33:54.132Z",
#             "temporal_end": "2023-01-31T11:35:48.593Z",
#         },
#         "profile_metadata": {
#             "url": "https://raw.githubusercontent.com/stelar-eu/data-profiler/main/examples/output/timeseries_profile.json",
#             "name": "Time series profile in JSON",
#             "description": "This is the profile of a time series in JSON format",
#             "resource_type": "Tabular",
#             "format": "JSON",
#             "resource_tags": ["Profile", "Computed with STELAR Profiler"],
#         },
#     },
# )
# @app.output(schema.ResponseAmbiguous, status_code=200)
# @app.doc(tags=["Publishing Operations"], security=security_doc)
@token_active
def api_dataset_publish(json_data):
    """Publish a new dataset in the Catalog.

    Registers metadata about a dataset and its associated resources (e.g., a data profile) in CKAN.
    The actual dataset will not be stored in the Catalog. The user will become the publisher of this dataset.

    Args:
        data: A JSON with metadata information provided by the publisher about the new dataset.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/publish -d '{"basic_metadata":{"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Bavaria"}]},"extra_metadata":{"INSPIRE theme":"Imagery","theme": ["Earth Sciences", "Landuse", "http://eurovoc.europa.eu/4630"], "language": ["ca", "en", "es"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]},"startDate":"2023-01-31T11:33:54.132Z", "endDate":"2023-01-31T11:35:48.593Z"},"profile_metadata":{"file":"/data/examples/timeseries_profile.json", "name": "Time series profile in JSON", "description": "This is the profile of a time series in JSON format", "format": "JSON", "resource_tags": [{"key": "Resource type", "value": "Profile"}, {"key": "Process", "value": "Computed with STELAR Profiler"}]}}'

    config = current_app.config["settings"]

    if request.headers:
        if request.headers.get("Api-Token") is not None:
            package_headers, resource_headers = utils.create_CKAN_headers(
                get_demo_ckan_token()
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    if request.data:
        metadata = request.data
        specs = json.loads(
            metadata.decode("utf-8")
        )  # json.loads(json.dumps(str(request.data)))
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No metadata provided for publishing in the Catalog. Please specify metadata for the dataset you wish to publish."
                ],
            },
        }
        return jsonify(response)

    arr_resp = []

    # Register the new dataset with the basic metadata
    if specs.get("basic_metadata") is not None:
        basic_metadata = specs["basic_metadata"]
        # Also create the name of the new CKAN package from its title (assuming that this is unique)
        basic_metadata["name"] = re.sub(r"[\W_]+", "_", basic_metadata["title"]).lower()
        # Convert the tags into the format required by CKAN
        basic_metadata["tags"] = utils.handle_keywords(basic_metadata["tags"])
        # Internal call to find the organization where the user belongs to (derived from API token)
        resp_org = api_user_editor()
        if resp_org["success"]:
            org_json = resp_org["result"]
            if len(org_json) > 0:
                for item in org_json:
                    if (
                        item["type"] == "organization"
                        and item["state"] == "active"
                        and item["capacity"] in ("admin", "editor")
                    ):
                        basic_metadata["owner_org"] = org_json[0][
                            "name"
                        ]  # CAUTION! Taking the first organization where this user is editor
                        break

        # Make a POST request to the CKAN API with the basic metadata
        resp_basic = requests.post(
            config["CKAN_API"] + "package_create",
            json=basic_metadata,
            headers=package_headers,
        )  # auth=HTTPBasicAuth(config.username, config.password))
        arr_resp.append(resp_basic.json())
    #        print(resp_basic.text)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No basic metadata provided for publishing in the Catalog. Please specify some basic metadata (title, description, tags, etc.) for the dataset you wish to publish."
                ],
            },
        }
        return jsonify(response)

    # Get the id of the newly created package in order to associate any remaining information (extras, resources)
    if resp_basic.status_code == 200:
        package_id = resp_basic.json()["result"]["id"]
    #        print("package_id: ", package_id)
    else:
        return (
            resp_basic.json()
        )  # Failed to publish the dataset with the basic metadata provided; CKAN response will specify the reason

    # Handle other user-specified metadata as extras
    # Also store values in custom tables for profiles in KLMS schema in the database
    if specs.get("extra_metadata") is not None:
        # Convert this metadata to a JSON array with {"key":"...", "value":"..."} pairs as required to be stored as extras in CKAN
        extra_metadata = {}
        extra_metadata["id"] = (
            package_id  # Must specify the id of the newly created package
        )
        extra_metadata["extras"] = utils.handle_extras(specs["extra_metadata"])
        # Make a POST request to the CKAN API to patch the newly created package with the extra metadata
        resp_extras = requests.post(
            config["CKAN_API"] + "package_patch",
            json=extra_metadata,
            headers=package_headers,
        )  # auth=HTTPBasicAuth(config.username, config.password))
        arr_resp.append(resp_extras.json())
    else:
        resp_extras = {
            "success": True,
            "help": request.url,
            "warning": {
                "__type": "No specifications",
                "name": [
                    "Warning: No extra metadata provided for publishing this dataset in the Catalog. You may still apply a CKAN package_patch request to include such extra metadata to this dataset in the future."
                ],
            },
        }
        arr_resp.append(resp_extras)

    # Handle profile metadata as a resource
    # TODO: Replace with the respective API function?
    if specs.get("profile_metadata") is not None:
        resource_metadata = specs["profile_metadata"]
        resource_metadata["package_id"] = (
            package_id  # Must specify the id of the newly created package
        )
        if resource_metadata.get("file") is not None:
            # Make a POST request to the CKAN API to upload the file from the specified path
            with open(resource_metadata["file"], "rb") as f:
                #                print('Resource file found!')
                resp_resource = requests.post(
                    config["CKAN_API"] + "resource_create",
                    data=resource_metadata,
                    headers=resource_headers,
                    files=[("upload", f)],
                )
                arr_resp.append(resp_resource.json())
                # Also ingest profile information into PostgreSQL according to KLMS schema
                resource_id = resp_resource.json()["result"]["id"]
                #                print("RESOURCE ID: ", resource_id)
                f1 = open(resource_metadata["file"])
                profile = json.load(f1)
                # Distinguish handling according to Profile type
                sql_commands = utils.extractProfileProperties(resource_id, profile)
                for sql in sql_commands:
                    #                    print(sql)
                    utils.execSql(sql)
        elif resource_metadata.get("url") is not None:
            # Make a POST request to the CKAN API to link the file from the specified URL
            resp_resource = requests.post(
                config["CKAN_API"] + "resource_create",
                data=resource_metadata,
                headers=resource_headers,
            )
            arr_resp.append(resp_resource.json())
        else:
            resp_resource = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "No specifications",
                    "name": [
                        "No profile metadata were associated with this dataset in the Catalog. Please provide a path or a publicly accessible URL where this file is available."
                    ],
                },
            }
            arr_resp.append(resp_resource)
    else:
        resp_resource = {
            "success": True,
            "help": request.url,
            "warning": {
                "__type": "No specifications",
                "name": [
                    "Warning: No profile metadata will be associated with this dataset in the Catalog. You may still apply a resource/upload request to attach such profiling information to this dataset in the future."
                ],
            },
        }
        arr_resp.append(resp_resource)

    # Examine collected responses to compose the overall response
    success = True
    result = []
    for idx, resp in enumerate(arr_resp):
        success &= resp["success"]
        result.append(resp)

    response = {"success": success, "help": request.url, "result": result}
    return jsonify(response)


@app.route("/api/v1/profile/publish", methods=["POST"])
@app.input(
    schema.Profile,
    location="json",
    example={
        "profile_metadata": {
            "package_id": "test_data_api_1",
            "file": "/data/examples/single_field_LAI-2.json",
            "name": "LAI profile in JSON",
            "description": "This is the profile of the Leaf Area Index in JSON format",
            "format": "JSON",
            "resource_type": "Raster",
            "resource_tags": ["Profile", "Computed with STELAR Profiler"],
        }
    },
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Publishing Operations"], security=security_doc)
@token_active
def api_profile_publish(json_data):
    """Upload a profile as a resource to an existing dataset in CKAN. The user will become the publisher of this profile.

    Args:
        data: A JSON with all metadata information provided by the publisher about the profile.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/profile/publish -d '{"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}}'

    config = current_app.config["settings"]

    if request.headers:
        if request.headers.get("Api-Token") is not None:
            package_headers, resource_headers = utils.create_CKAN_headers(
                get_demo_ckan_token()
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    if request.data:
        metadata = json.loads(
            request.data.decode("utf-8")
        )  # json.loads(json.dumps(str(request.data)))
        if "profile_metadata" in metadata:
            resource_metadata = metadata["profile_metadata"]
        else:
            response = {
                "success": False,
                "help": request.url + "?q=",
                "error": {
                    "__type": "No specifications",
                    "name": [
                        "No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload."
                ],
            },
        }
        return jsonify(response)

    if resource_metadata.get("file") is not None:
        # Make a POST request to the CKAN API to upload the file from the specified path
        with open(resource_metadata["file"], "rb") as f:
            #            print('Profile information found!')
            response = requests.post(
                config["CKAN_API"] + "resource_create",
                data=resource_metadata,
                headers=resource_headers,
                files=[("upload", f)],
            )
            # Also ingest profile information into PostgreSQL according to KLMS schema
            resource_id = response.json()["result"]["id"]
            #            print("RESOURCE ID: ", resource_id)
            f1 = open(resource_metadata["file"])
            profile = json.load(f1)
            # Distinguish handling according to Profile type
            sql_commands = utils.extractProfileProperties(resource_id, profile)
            for sql in sql_commands:
                #                print(sql)
                utils.execSql(sql)
            return response.json()
    elif resource_metadata.get("url") is not None:
        # Make a POST request to the CKAN API to link the file from the specified URL
        response = requests.post(
            config["CKAN_API"] + "resource_create",
            data=resource_metadata,
            headers=resource_headers,
        )
        return response.json()
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No profile metadata were associated with this dataset in the Catalog. Please provide a path or a publicly accessible URL where this file is available."
                ],
            },
        }
        return response.json()


########### TESTING ONLY #################################
@app.route("/api/v1/profile/store", methods=["POST"])
@app.input(
    schema.Profile,
    location="json",
    example={
        "profile_metadata": {
            "package_id": "test_data_api_1",
            "file": "/data/examples/single_field_LAI-2.json",
            "name": "LAI profile in JSON",
            "description": "This is the profile of the Leaf Area Index in JSON format",
            "format": "JSON",
            "resource_type": "Raster",
            "resource_tags": ["Profile", "Computed with STELAR Profiler"],
        }
    },
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["Publishing Operations"], security=security_doc)
@token_active
def api_profile_store(json_data):
    """Store profile information directly in the PostgreSQL database. The respective resource must correspond to an existing dataset in CKAN. The user will become the publisher of this profile.

    Args:
        data: A JSON with all metadata information provided by the publisher about the profile. Must include the profile information in a nested JSON.

    Returns:
        A JSON with the response to the storage request.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/profile/publish -d '{"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}}'

    # config = current_app.config["settings"]

    if request.headers:
        if request.headers.get("Api-Token") is not None:
            package_headers, resource_headers = utils.create_CKAN_headers(
                request.headers["Api-Token"]
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    if request.data:
        metadata = json.loads(
            request.data.decode("utf-8")
        )  # json.loads(json.dumps(str(request.data)))
        if "profile_metadata" in metadata:
            # Extract the profile data and the CKAN resource identifier (will be part of primary keys in the database)
            profile = metadata["profile_metadata"]["profile_data"]
            resource_id = metadata["profile_metadata"]["resource_id"]
            # Distinguish handling according to Profile type
            sql_commands = utils.extractProfileProperties(resource_id, profile)
            for sql in sql_commands:
                #                print(sql)
                utils.execSql(sql)
            response = {"success": True, "help": request.url, "result": ""}
            return jsonify(response)
        else:
            response = {
                "success": False,
                "help": request.url + "?q=",
                "error": {
                    "__type": "No specifications",
                    "name": [
                        "No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload."
                ],
            },
        }
        return jsonify(response)


# @app.route("/api/v1/resource/link", methods=["POST"])
# @app.input(
#     schema.Resource,
#     location="json",
#     example={
#         "resource_metadata": {
#             "package_id": "test_data_api_1",
#             "url": "https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson",
#             "name": "Test GeoJSON resource",
#             "description": "This is the test resource in GeoJSON format",
#             "format": "GeoJSON",
#             "resource_type": "Tabular",
#             "resource_tags": ["Link to external resource", "Found in the Web"],
#         }
#     },
# )
# @app.output(schema.ResponseOK, status_code=200)
# @app.doc(tags=["Publishing Operations"], security=security_doc)
# @token_active
def api_resource_link(json_data):
    """Associate a resource (with its URL) to an existing dataset in CKAN. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new resource.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/resource/link -d '{"resource_metadata": {"package_id": "test_data_api_1", "url":"https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson", "name": "Test GeoJSON resource", "description": "This is the test resource in GeoJSON format", "format": "GeoJSON", "resource_tags": ["Link to external resource", "Found in the Web"]}}'

    config = current_app.config["settings"]

    if request.headers:
        if request.headers:
            package_headers, resource_headers = utils.create_CKAN_headers(
                get_demo_ckan_token()
            )
        else:
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": [
                        "No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "Authorization Error",
                "name": [
                    "No headers specified. Please specify headers for your request, including a valid API TOKEN."
                ],
            },
        }
        return jsonify(response)

    if request.data:
        metadata = json.loads(
            request.data.decode("utf-8")
        )  # json.loads(json.dumps(str(request.data)))
        if "resource_metadata" in metadata:
            resource_metadata = metadata["resource_metadata"]
        else:
            response = {
                "success": False,
                "help": request.url + "?q=",
                "error": {
                    "__type": "No specifications",
                    "name": [
                        "No metadata provided for publishing this resource in the Catalog. Please specify metadata for the resource you wish to publish."
                    ],
                },
            }
            return jsonify(response)
    else:
        response = {
            "success": False,
            "help": request.url,
            "error": {
                "__type": "No specifications",
                "name": [
                    "No metadata provided for publishing this resource in the Catalog. Please specify metadata for the resource you wish to publish."
                ],
            },
        }
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(
        config["CKAN_API"] + "resource_create",
        data=resource_metadata,
        headers=resource_headers,
    )

    if response.status_code == 200:
        # Also ingest profile information into PostgreSQL according to KLMS schema
        resource_id = response.json()["result"]["id"]
        # print("RESOURCE ID: ", resource_id)
        # Distinguish handling according to Profile type
        sql_commands = utils.extractResourceProperties(resource_id, resource_metadata)
        for sql in sql_commands:
            utils.execSql(sql)

    return response.json()


# @app.route("/api/v1/workflow/statistics", methods=["POST"])
# @app.input(
#     schema.Workflow_Statistics,
#     location="json",
#     example={
#         "workflow_tags": ["A3-4"],
#         "metrics": ["food_tags", "total_tags", "f1_micro", "f1_macro", "f1_weighted"],
#         "parameters": ["k", "model"],
#     },
# )
# # @app.output(schema.ResponseOK, status_code=200)
# @app.doc(tags=["Tracking Operations"], security=security_doc)
# @token_active
def api_workflow_statistics(json_data):
    """Fetch statistics for each Worfklow Execution for a specific group of
    workflow executions.

    Args:
        data: A JSON with the id of the Worfklow Execution and the state of the task.

    Returns:
        A JSON with the result of the update.
    """

    # EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/workflow/statistics -d '{"workflow_tags": ["A3-4"], "metrics": ['food_tags', 'total_tags', 'f1_micro', 'f1_macro', 'f1_weighted'], "parameters": ['k', 'model']}'

    workflow_tags = json_data["workflow_tags"]
    parameters = json_data["parameters"]
    metrics = json_data["metrics"]

    try:
        response = sql_utils.workflow_statistics(workflow_tags, parameters, metrics)
        if not response:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Workflow Statistics cannot not be returned.",
                    }
                ),
                500,
            )
        return jsonify({"success": True, "result": response}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


###########################################################


@app.template_filter("datetimeformat")
def datetimeformat(value, format="%d-%m-%Y %H:%M"):
    # Convert string to datetime object if it's a string
    try:
        datetime_obj = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")
        return datetime_obj.strftime(format)
    except ValueError:
        return value  # Return the original value if it can't be formatted


@app.teardown_appcontext
def teardown_dbconn(exception):
    dbconn = g.pop("dbconn", None)
    if dbconn is not None:
        get_mdb_pool().putconn(dbconn)


def json_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a JSON file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_file, "r") as f:
        config_data = json.load(f)
    return config_data


def yaml_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a YAML file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_file, "r") as f:
        config_data = yaml.safe_load(f)
    return config_data


def main(app):
    app.config["settings"] = {
        "FLASK_RUN_HOST": os.getenv("FLASK_RUN_HOST", "0.0.0.0"),
        "FLASK_RUN_PORT": os.getenv("FLASK_RUN_PORT", "80"),
        "FLASK_DEBUG": os.getenv("FLASK_DEBUG", "True").lower() == "true",
        "API_TITLE": os.getenv("API_TITLE", "KLMS Data API"),
        "API_VERSION": os.getenv("API_VERSION", "1.0.0"),
        "SPEC_FORMAT": os.getenv("API_SPEC_FORMAT", "json"),
        "AUTO_SERVERS": os.getenv("API_AUTO_SERVERS", "True").lower() == "true",
        "AUTO_TAGS": os.getenv("API_AUTO_TAGS", "False").lower() == "true",
        "AUTO_OPERATION_SUMMARY": os.getenv(
            "API_AUTO_OPERATION_SUMMARY", "True"
        ).lower()
        == "true",
        "AUTO_OPERATION_DESCRIPTION": os.getenv(
            "API_AUTO_OPERATION_DESCRIPTION", "True"
        ).lower()
        == "true",
        "TAGS": json.loads(
            os.getenv(
                "API_TAGS",
                '[{"name": "KLMS", "description": "Knowledge Lake Management System"}, {"name": "STELAR", "description": "Spatio-TEmporal Linked data tools for the AgRi-food data space"}]',
            )
        ),
        "DESCRIPTION": os.getenv(
            "API_DESCRIPTION",
            "Data API for managing resources in STELAR Knowledge Lake Management System",
        ),
        "TERMS_OF_SERVICE": os.getenv(
            "API_TERMS_OF_SERVICE", "http://stelar-project.eu/"
        ),
        "CONTACT": json.loads(
            os.getenv(
                "API_CONTACT",
                '{"name": "API Support", "url": "<API-URL>", "email": "<CONTACT-EMAIL_ADDRESS>"}',
            )
        ),
        "LICENSE": json.loads(
            os.getenv(
                "API_LICENSE",
                '{"name": "Apache 2.0", "url": "http://www.apache.org/licenses/LICENSE-2.0.html"}',
            )
        ),
        "CKAN_API": f"{os.getenv('CKAN_SITE_URL', 'http://<CKAN-HOST>')}/api/3/action/",
        "CKAN_ADMIN_TOKEN": os.getenv("CKAN_ADMIN_TOKEN", ""),
        "dbname": os.getenv("POSTGRES_DB", "<DB-NAME>"),
        "dbuser": os.getenv("POSTGRES_USER", "<DB-USERNAME>"),
        "dbpass": os.getenv("POSTGRES_PASSWORD", "<DB-PASSWORD>"),
        "dbhost": os.getenv("POSTGRES_HOST", "<DB-HOST>"),
        "dbport": os.getenv("POSTGRES_PORT", "5432"),
        "KEYCLOAK_URL": os.getenv("KEYCLOAK_URL", "http://keycloak:8080"),
        "KEYCLOAK_CLIENT_ID": os.getenv("KEYCLOAK_CLIENT_ID", "stelar-api"),
        "KEYCLOAK_CLIENT_SECRET": os.getenv("KEYCLOAK_CLIENT_SECRET", "none"),
        "REALM_NAME": os.getenv("REALM_NAME", "master"),
        "SPARQL_ENDPOINT": os.getenv("SPARQL_ENDPOINT", "http://<ONTOP-HOST>/sparql"),
        "RANK_DEFAULT_TOPK": int(os.getenv("RANK_DEFAULT_TOPK", "10")),
        "RANK_MAX_TOPK": int(os.getenv("RANK_MAX_TOPK", "10000")),
        "RANK_AGG_ALGORITHM": os.getenv("RANK_AGG_ALGORITHM", "Bordacount"),
        "API_URL": os.getenv("API_URL", "http://stelarapi/"),
        "KLMS_DOMAIN_NAME": os.getenv("KLMS_DOMAIN_NAME", "stelar.gr"),
        "MAIN_INGRESS_SUBDOMAIN": os.getenv("MAIN_INGRESS_SUBDOMAIN", "klms"),
        "KEYCLOAK_SUBDOMAIN": os.getenv("KEYCLOAK_SUBDOMAIN", "kc"),
        "MINIO_API_SUBDOMAIN": os.getenv("MINIO_API_SUBDOMAIN", "minio"),
        "MINIO_API_EXT_URL": os.getenv("MINIO_API_EXT_URL", "***MISSING***"),
        "KEYCLOAK_EXT_URL": os.getenv("KEYCLOAK_EXT_URL", "***MISSING***"),
        "KEYCLOAK_ISSUER_URL": os.getenv("KEYCLOAK_ISSUER_URL", "***MISSING***"),
        "MAIN_EXT_URL": os.getenv("MAIN_EXT_URL", "***MISSING***"),
        "S3_CONSOLE_URL": os.getenv("MINIO_CONSOLE_URL", ""),
        "SMTP_SERVER": os.getenv("SMTP_SERVER", "stelar.gr"),
        "SMTP_PORT": os.getenv("SMTP_PORT", "465"),
        "SMTP_EMAIL": os.getenv("SMTP_EMAIL", "info@stelar.gr"),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", "None"),
        "execution": {"engine": os.getenv("EXECUTION_ENGINE", "none")},
    }

    # Apply configuration settings for this API
    app.title = app.config["settings"]["API_TITLE"]
    app.version = app.config["settings"]["API_VERSION"]
    app.config["SECURITY_SCHEMES"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }

    # Configure the metadata database connection pool
    if app.config["settings"]["dbname"] != "<DB-NAME>":
        initialize_mdb_pool(app.config["settings"])

    # Configure the CKAN client
    initialize_ckan_client(app.config["settings"])

    # Configure execution
    execution.configure(app.config["settings"])
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_proto=1, x_for=1, x_host=1, x_port=1, x_prefix=1
    )
    # Execution of the application will happen from gunicorn after create_app returns the app instance


# This entry point is used with gunicorn -b -w ....
def create_app():
    main(app)
    with app.app_context():
        authz_module.load_authorization_schema()
    # Return the application instance so that gunicorn can run it.
    return app
