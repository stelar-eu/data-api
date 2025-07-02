# flake8: noqa: E402
#
# We need to configure logging as the first thing to do...
#
import logging
import traceback

import authz_module
import logsys

logsys.configure()

import json
import os
import re
import uuid
from datetime import date
from datetime import datetime as datetime
from datetime import timedelta
from urllib.parse import urljoin, urlparse, urlunparse

import pandas as pd
import psycopg2
import redis
import requests
import yaml
from apiflask import APIFlask
from flask import current_app, g, jsonify, redirect, request, url_for
from flask.json.provider import DefaultJSONProvider

# Import Redis Session support
from flask_session import Session

from collections import OrderedDict

import execution

# Input schemata for validating several API requests
import schema
import sql_utils

# Auxiliary custom functions & SQL query templates for ranking
import utils
from auth import security_doc, token_active
from backend.ckan import initialize_ckan_client
from backend.pgsql import get_mdb_pool, initialize_mdb_pool
from backend.registry import initialize_registry_client

# Import demo token creator
from demo_t import get_demo_ckan_token
from routes.auth_tool import auth_tool_bp
from routes.catalog import catalog_bp
from routes.dashboard import dashboard_bp
from routes.publisher import publisher_bp
from routes.settings import settings_bp
from routes.users import api_user_editor, users_bp
from routes.workflows import workflows_bp
from routes.llm_search import llmsearch_bp

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
app.register_blueprint(auth_tool_bp, url_prefix="/api/v1/auth")
app.register_blueprint(catalog_bp, url_prefix="/api/v2")
app.register_blueprint(workflows_bp, url_prefix="/api/v2")
app.register_blueprint(llmsearch_bp, url_prefix="/api/v2/llm")

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


def sort_recursive(value):
    """Return an OrderedDict with every nested level alphabetically sorted."""
    if isinstance(value, dict):
        return OrderedDict(
            (k, sort_recursive(v))
            for k, v in sorted(value.items(), key=lambda x: x[0].lower())
        )
    if isinstance(value, list):
        return [sort_recursive(v) for v in value]
    return value


def extract_number(value):
    """
    Find the first integer or decimal in the string and return it as a float.
    If nothing matches, return None.
    """
    m = re.search(r"-?\d+(\.\d+)?", str(value))
    return float(m.group(0)) if m else None


app.jinja_env.filters["sort_recursive"] = sort_recursive
app.jinja_env.filters["format_datetime"] = format_datetime
app.jinja_env.filters["extract_number"] = extract_number
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
@app.route("/api/v1/workflow/input/dataset", methods=["GET"])
@app.input(
    schema.Identifier,
    location="query",
    example="id=82aaa2df-be92-46ee-a36b-cc59122a5d5b",
)
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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
@app.doc(tags=["KG Search Operationss"])
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


def resolve_image_registry_address(addr: str, env: dict) -> str:
    """Resolve the image registry address based on deployment info.

    `addr` needs to be one of "auto", "internal", "external",
    "localhost", or a specific IP address (containing dots and possibly a port)

    "auto" examines the REGISTRY_EXT_URL and specifically the protocol (http or https).
    If it is https, then the "external" registry address will be used,
    else the "internal" registry address will be used.

    "external" basically translated something like "img.stelar.gr", by taking the
    url in REGISTRY_EXT_URL and removing the protocol part.

    "internal" is the address taken as  $QUAY_SERVICE_HOST:$QUAY_SERVICE_PORT,
    which is the internal address of the quay service in the Kubernetes cluster.
    This is used on minikube (development) deployments, but it requires further
    configuration (allowing non-tls access from the kubelet to the registry, is a
    creation-time configuration option in minikube).

    "localhost"  or any string containing dots (.) and optionally a port (like :3334)
    is taken as a literal address. Again, this should only be used for testing purposes.

    Args:
        addr: A string representing the image registry address.
        env: A dictionary containing environment variables, such as REGISTRY_EXT_URL.

    Returns:
        A string with the resolved image registry address.
    """

    try:
        if addr == "auto":
            if env["REGISTRY_EXT_URL"].startswith("https://"):
                return resolve_image_registry_address("external", env)
            else:
                return resolve_image_registry_address("internal", env)

        elif addr == "external":
            registry = re.sub(r"^https?://", "", env["REGISTRY_EXT_URL"])
            return registry

        elif addr == "internal":
            return f"{env['QUAY_SERVICE_HOST']}:{env['QUAY_SERVICE_PORT']}"

        else:
            return addr  # This is either "localhost" or a specific IP address

    except KeyError as e:
        logger.critical(f"Missing environment variable: {e}")
        # If the required environment variables are not set, we cannot resolve the address
        return None
    except Exception:
        # On failure, leave this unconfigured
        logger.exception("Error resolving image registry address")
        # This is not a critical error, so we just return None
        return None


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
        "CKAN_ENCODE_KEY": os.getenv("CKAN_ENCODE_KEY", ""),
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
        "REGISTRY_SUBDOMAIN": os.getenv("REGISTRY_SUBDOMAIN", "img"),
        "MINIO_API_SUBDOMAIN": os.getenv("MINIO_API_SUBDOMAIN", "minio"),
        "MC_INSECURE": os.getenv("MC_INSECURE", "false"),
        "MINIO_ROOT_PASSWORD": os.getenv("MINIO_ROOT_PASSWORD", "***MISSING***"),
        "MINIO_ROOT_USER": os.getenv("MINIO_ROOT_USER", "***MISSING***"),
        "MINIO_API_EXT_URL": os.getenv("MINIO_API_EXT_URL", "***MISSING***"),
        "LLM_SEARCH_ENABLED": os.getenv("ENABLE_LLM_SEARCH", "False").lower() == "true",
        "LLM_SEARCH_URL": os.getenv("LLM_SEARCH_URL", "***MISSING***"),
        "LLM_GROQ_API_KEY": os.getenv("LLM_GROQ_API_KEY", "***MISSING***"),
        "KEYCLOAK_EXT_URL": os.getenv("KEYCLOAK_EXT_URL", "***MISSING***"),
        "KEYCLOAK_ISSUER_URL": os.getenv("KEYCLOAK_ISSUER_URL", "***MISSING***"),
        "MAIN_EXT_URL": os.getenv("MAIN_EXT_URL", "***MISSING***"),
        "REGISTRY_API": os.getenv("REGISTRY_API", "http://quay:8080"),
        "REGISTRY_EXT_URL": os.getenv("REGISTRY_EXT_URL", "***MISSING***"),
        "S3_CONSOLE_URL": os.getenv("MINIO_CONSOLE_URL", ""),
        "REDIS_HOST": os.getenv("REDIS_SERVICE_HOST", "redis"),
        "REDIS_PORT": os.getenv("REDIS_SERVICE_PORT", "6379"),
        "SMTP_SERVER": os.getenv("SMTP_SERVER", "stelar.gr"),
        "SMTP_PORT": os.getenv("SMTP_PORT", "465"),
        "SMTP_EMAIL": os.getenv("SMTP_EMAIL", "info@stelar.gr"),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", "None"),
        "execution": {
            "engine": os.getenv("EXECUTION_ENGINE", "none"),
            # The below needs to be one of "auto", "internal", "external",
            # "localhost", or a specific IP address (containing dots and possibly a port)
            # See resolve_registry_address() for details.
            "image_registry_address": resolve_image_registry_address(
                os.getenv("IMAGE_REGISTRY_ADDRESS", "auto"), os.environ
            ),
            "image_registry_org": os.getenv("IMAGE_REGISTRY_ORG", "stelar"),
            "namespace": os.getenv("API_NAMESPACE"),
            "api_url": os.getenv("API_URL", "http://stelarapi/"),
            "default_profile": {
                "restart_policy": "Never",
                "image_pull_policy": "Always",
                "image_pull_secrets": ["stelar-registry-secret"],
                # Resource limits:
                # uncomment the below lines to set resource limits and requests.
                # TODO: Eventually, these limits could be given by deployment config.
                #
                # "cpu_limit": "1",
                # "cpu_request": "0.5",
                # "memory_limit": "1Gi",
                # "memory_request": "512Mi",
                "ttl_seconds_after_finished": 60 * 60 * 24,
                "backoff_limit": 3,
            },
        },
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

    # Configure the Registry client
    initialize_registry_client(app.config["settings"])

    # Configure execution
    execution.configure(app.config["settings"])
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_proto=1, x_for=1, x_host=1, x_port=1, x_prefix=1
    )

    # Configure Flask to use Redis for session management
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=60)
    app.config["SESSION_USE_SIGNER"] = True
    app.config["SESSION_KEY_PREFIX"] = "stelar_session:"
    app.config["SESSION_REDIS"] = redis.StrictRedis(
        host=os.getenv("REDIS_SERVICE_HOST", "redis"),
        port=os.getenv("REDIS_SERVICE_PORT", "6379"),
        db=0,
        decode_responses=False,
    )

    Session(app)

    # Execution of the application will happen from gunicorn after create_app returns the app instance


# This entry point is used with gunicorn -b -w ....
def create_app():
    main(app)
    try:
        with app.app_context():
            authz_module.load_authorization_schema()
    except Exception as e:
        logger.error("Failed to load authorization schema: %s", e)
        logger.error("Traceback: %s", traceback.format_exc())
    # Return the application instance so that gunicorn can run it.
    return app
