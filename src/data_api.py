import flask
import requests
import json
import re
import sys
import psycopg2
import yaml
import os
import pandas as pd
import uuid
import os
import subprocess
import urllib

#for keycloak integration with the api
from jose import jwt, JWTError
from requests.models import Response
import logging
from src.auth import auth, security_doc, policy_enforcer

from psycopg2.extras import RealDictCursor
from flask import request, jsonify, current_app, redirect, session, url_for
from apiflask import APIFlask
from apiflask.fields import Dict, Nested

from flask.json import JSONEncoder
from datetime import datetime as datetime
from datetime import date

# Auxiliary custom functions & SQL query templates for ranking
import utils
import sql_utils

#from container_utils import create_container
import execution


#Import demo token creator
from demo_t import get_demo_ckan_token

# Input schemata for validating several API requests
import schema

#################### BLUEPRINT IMPORTS #####################
# Import the blueprints for the logical parts of the API

#### USERS BP ####
from routes.users import users_bp
from routes.users import api_user_editor

#### TASK BPs ####
from routes.tasks import tasks_bp

#### PUBLISHER BP ####
from routes.publisher import publisher_bp

#### DASHBOARD BP ####
from routes.dashboard import dashboard_bp
from routes.publisher import publisher_bp
from routes.settings import settings_bp
from routes.admin import admin_bp
from routes.search_ops import search_ops_bp
from routes.publish_ops import publish_ops_bp
from routes.workflow_ops import workflow_ops_bp
from routes.catalog import catalog_bp
from routes.knowledge_graph import knowledge_graph_bp

############################################################

# Create an instance of this API; by default, its OpenAPI-compliant specification will be generated under folder /specs
app = APIFlask(__name__, spec_path='/specs', docs_path ='/docs')

app.secret_key = 'secretkey123'

app.config.from_prefixed_env()

logging.basicConfig(level=logging.DEBUG)

################## BLUEPRINT REGISTRATION ##################

# Blueprints are used to split the API into logical parts, 
# such as User Management, Catalog Management,
# Workflow/Execution management etc.

app.register_blueprint(users_bp, url_prefix='/api/v1/catalog')
app.register_blueprint(tasks_bp, url_prefix='/api/v1/task')
app.register_blueprint(dashboard_bp, url_prefix='/console/v1')
app.register_blueprint(publisher_bp, url_prefix='/console/v1')
app.register_blueprint(settings_bp, url_prefix='/console/v1/settings')
app.register_blueprint(admin_bp, url_prefix='/console/v1/admin')
app.register_blueprint(search_ops_bp, url_prefix='/api/v1')
app.register_blueprint(publish_ops_bp, url_prefix='/api/v1')


app.register_blueprint(catalog_bp, url_prefix='/api/v1/catalog')
app.register_blueprint(workflow_ops_bp, url_prefix='/api/v1/workflow')
app.register_blueprint(knowledge_graph_bp, url_prefix='/api/v1/kg')


############################################################

# Custom class to retain original ISO format like 'yyyy-mm-dd hh:mm:ss.m' in date/time/timestamp values
class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        try:
            if isinstance(obj, date):
                return obj.isoformat()
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)

app.json_encoder = CustomJSONEncoder

################################## AUTHENTICATION ########################################

# # Authenticate API requests using tokens (issued by CKAN)
# auth = HTTPTokenAuth(scheme='ApiKey', header='Api-Token')


# @auth.verify_token
# def api_verify_token(token):
#     """Register a callback to verify that the token is valid for POST requests that require authentication. GET requests do not require authentication in CKAN.

#     Args:
#         token: A token issued by the user through the CKAN GUI.

#     Returns:
#         A boolean: True, if the token is valid; False, otherwise.
#     """

#     config = current_app.config['settings']

#     user_headers = { 'X-CKAN-API-Key' : token }

#     # Make a POST request to the CKAN API with the token to check access to user information
#     response = requests.post(config['CKAN_API']+'user_show', headers=user_headers) 

#     if response.json()['success']:
#         return True
#     else:
#         return False

# app.config['keycloak_settings'] = {
#     'KEYCLOAK_ISSUER': 'https://<keycloak-domain>/auth/realms/master',
#     'KEYCLOAK_CLIENT_ID': 'stelar-api',
#     'KEYCLOAK_CLIENT_SECRET': 'iQTNNRsMxuVYqcL2KiDyCqtfVryxxaRw',  # Optional: only if you're using confidential clients
#     'KEYCLOAK_REDIRECT_URI': 'http://localhost:5000/callback',  # Your redirect URI
# }


# Redirect user to Keycloak login page
@app.route('/login')
@app.doc(tags=["KLMS Data API"])
def login():
    config = current_app.config['settings']
    keycloak_login_url = (
        "https://"+config['KEYCLOAK_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']+"/realms/"+config['REALM_NAME']+"/protocol/openid-connect/auth"
        +"?client_id="+config['KEYCLOAK_CLIENT_ID']
        +"&response_type=code"
        +"&redirect_uri=https://"+config['MAIN_INGRESS_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']+"/stelar/callback"
        +"&scope=openid"
    )
    return redirect(keycloak_login_url)

# Callback endpoint to handle Keycloak's response
@app.route('/callback')
@app.doc(tags=["KLMS Data Testing"])
def callback():
    code = request.args.get('code')
    if not code:
        return "Authorization code not provided", 400
    
    config = current_app.config['settings']
    
    # Exchange authorization code for an access token
    token_url = config['KEYCLOAK_URL']+"/realms/"+config['REALM_NAME']+"/protocol/openid-connect/token"
    payload = {
        'grant_type': 'authorization_code',
        'client_id': config['KEYCLOAK_CLIENT_ID'],
        'client_secret': config['KEYCLOAK_CLIENT_SECRET'],
        'code': code,
        'redirect_uri': 'https://'+config['MAIN_INGRESS_SUBDOMAIN']+'.'+config['KLMS_DOMAIN_NAME']+'/stelar/callback',
    }

    response = requests.post(token_url, data=payload)
    token_data = response.json()

    if 'access_token' in token_data:
        session['access_token'] = token_data['access_token']
        return jsonify({"message": "Keycloak authenticated!", "token": token_data['access_token']})
    else:
        return "Failed to get access token", 400

# Protect this endpoint with token verification
@app.route('/secure-endpoint', methods=['GET'])
@auth.login_required
@app.doc(tags=["KLMS Testing"], security=security_doc)
def secure_endpoint():
    return jsonify({"message": "Authenticated with Keycloak!"})

################################## ENTRY POINT ########################################


@app.route('/', methods=['GET'])
@app.output(schema.ResponseOK, status_code=200)
@app.doc(responses=[404], tags=['KLMS Data API'])   # ,summary='Entry point to the API'
def home():
    """Entry point to the Data API of Knowledge Lake Management System.

    Args:

    Returns:
        A JSON with basic information about the API.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/ 
    
    response = {
        'help': request.base_url,
        'success': True,
        'result': {
            'message':'Data API for managing resources in STELAR Knowledge Lake Management System.',
            'OpenAPI specifications':request.base_url+'specs',
            'Swagger UI':request.base_url+'docs',
            'Console':request.base_url+'console/v1/'
        }
    }

    return jsonify(response)

#    return '''<h1>STELAR Knowledge Lake Management System</h1><p>Prototype Data API for managing KLMS resources.</p><p>API specification is available <a href='/specs'>here</a>.<p>Interactive API documentation (Swagger UI) is available <a href='/docs'>here</a>.</p>'''



# Endpoint to return configuration as JSON
@app.route('/config', methods=['GET'])
@app.doc(tags=["KLMS Testing"], responses=[200])

def get_config():
    return jsonify(app.config['settings'])


################################## RANKING OPERATIONS ########################################

@app.route('/api/v1/catalog/rank', methods=['POST'])
@app.input(schema.Ranking, location='json', example={"rank_preferences":{"tags": ["Geospatial","POI"], "theme":["Land Use","Land Cover","Imagery"], "language":["en","el","fr"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}, "settings":{"k": 10, "algorithm": "threshold", "weights": [0.3,0.5,0.4] }})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Ranking Operations'], security=security_doc)
@auth.login_required
def api_catalog_rank(json_data):
    """Submit a rank request regarding specific metadata attributes (facets) to the Data Catalog.

    Args:
        json_data: A JSON with facet preferences for searching in the Data Catalog. Facet name should match a property specified in the STELAR Ontology.

    Returns:
        A JSON with datasets ranked by the specified facet(s). The matching score per facet criterion is also listed per returned dataset.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/rank -d '{"q":{"theme":"POI"}}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    sql = ''
    sql_id_filter = ''
    ids = []
    dict_df_facet_scores = {}   # dictionary with the returned input ranked lists per facet (key -> dataframe)
    k = config['RANK_MAX_TOPK']  # default top-k value (if not user-specified)
    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        actual_profile_attributes = set(specs['filter_preferences'].keys()).union(set(specs['rank_preferences'].keys()))
#        print("INITIAL PROFILE ATTRIBUTES", actual_profile_attributes)

        # STAGE #1: text-based keyword search targets SOLR (search engine for CKAN)
        if 'keywords' in specs:   # CASE #1(a): new keyword search
            q = '?q=' + ",".join("'{0}'".format(kw) for kw in specs['keywords'])   
#            print(q)
            # Submit a preliminary search request to CKAN to find packages qualifying to the specified keywords
            # Also include private datasets of the user's organization in the results
            resp_basic = requests.get(config['CKAN_API']+'package_search'+q+'&include_private=True&fl=*,score&rows='+str(config['RANK_MAX_TOPK'])+'&start=0', headers=package_headers)
            if resp_basic.status_code == 200:
                json_resp_basic = resp_basic.json()
                #FIXME: Handle large number of returned id's -> not efficient when filtering with SQL
                if json_resp_basic['success']:  # Results from keyword-based search only
                    results = json_resp_basic['result']['results']
                    ids = [res['id'] for res in results if 'id' in res]
#                    print('keyword results:',len(ids))
        elif 'ids' in specs:  # CASE #1(b): Identifiers of datasets already qualifying keyword search criteria
            if len(specs['ids']) > 0:
                ids = specs['ids']
        if len(ids) > 0:   # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids)  
        else:   # No results from filtering, no sense to continue with further filtering
            response = {'help': request.url, 'result': {'count': 0, 'facets': {}, 'results': [],'sort': 'score desc, metadata_modified desc'}, 'success': True}
            return jsonify(response)

        # STAGE #2: Apply any filtering criteria (NOT participating in the ranking)
        if 'filter_preferences' in specs:
            filter_sql_commands = utils.format_facet_preferences(specs['filter_preferences'], sql_id_filter, config['RANK_MAX_TOPK'])
            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            for key in filter_sql_commands.keys():
                sql = filter_sql_commands[key]
                results = utils.execSql(sql)
#                print(len(results), sql)
                filter_ids = [res['id'] for res in results if 'id' in res]
                if sql_id_filter == '':  # No keywords specified in search bar
                    ids = filter_ids
                else:  # Keep only matching id's
                    ids = [id for id in ids if id in filter_ids]
#                print(key, len(ids))
        if len(ids) > 0:   # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids) 
        else:   # No results from filtering, no sense to apply ranking
            response = {'help': request.url, 'result': {'count': 0, 'facets': {}, 'results': [],'sort': 'score desc, metadata_modified desc'}, 'success': True}
            return jsonify(response)

        # STAGE #3: Prepare SQL queries for each of the ranking preferences 
        if 'rank_preferences' in specs:
            rank_sql_commands = utils.format_facet_preferences(specs['rank_preferences'], sql_id_filter, config['RANK_MAX_TOPK'])
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
                    if not id in [d['id'] for d in results if 'id' in d]:
                        results.append({'id':id, 'score':0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)
#                # In case a 'value' column (concerning PROFILING) is returned in results, remember to include its values in the final results
#                if 'value' in dict_df_facet_scores[key].columns:
#                    profile_attributes.append(key)
#                    print(key)


            # Fetch values for all profiling metadata elements by submitting a SELECT query to the PostgreSQL database for the collected ids
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            actual_profile_attributes = actual_profile_attributes.intersection(utils.profile_attributes)
#            print("ACTUAL PROFILE ATTRIBUTES", actual_profile_attributes)
            for key in list(actual_profile_attributes):  #list(set(utils.profile_attributes) - set(rank_sql_commands.keys())):
                sql = utils.identifiers_sql_filter_template.replace('_VIEW',utils.sql_views[key]).replace('_IDS',sql_id_filter) 
#                print(key, '->', sql)
                results = utils.execSql(sql)
                print("PROFILING", key, len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if not id in [d['id'] for d in results if 'id' in d]:
                        results.append({'id':id, 'score':0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)

                input_lists.append(dict_df_facet_scores[key])

            # FIXME: REMOVE IF HANDLED BY THE FRONT-END    
            agg_scores = pd.DataFrame()   # No aggregated scores, report the original SOLR scores
    
            # Compute the final ranked list of all items applying the specified rank aggregation method (e.g., threshold)
#            agg_scores = ranking.combined_ranking(input_lists, specs['settings'])
#            ids = agg_scores.index.values  # In case no keywords and no filter criteria have been spcified; only rank preferences
#            print(agg_scores.index.values)
        elif 'settings' in specs:  # Settings for rank aggregation assume at least once facet specification
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary.']}}
            return jsonify(response)
        else:   # No ranking to be applied; only search filters
            specs['rank_preferences'] = {}  # Facets for ranking not specified
            agg_scores = pd.DataFrame()   # No aggregated scores, report the original SOLR scores
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary.']}}
        return jsonify(response)

    # Retrieve from CKAN all metadata for the datasets in the final (aggregated ranked) list
    # Also include private datasets of the user's organization in the results
    q='?q=' + ' OR '.join(['id:'+id for id in ids])
    response = requests.get(config['CKAN_API']+'package_search'+q+'&rows='+str(config['RANK_MAX_TOPK'])+'&start=0&include_private=True', headers=package_headers) 

    # Return the final list of results (the top-k ranked ones in case that ranking preferences are specified)
    return utils.assign_scores(response, agg_scores, dict_df_facet_scores, specs['rank_preferences'], list(actual_profile_attributes))


###########################################################

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d-%m-%Y %H:%M'):
    # Convert string to datetime object if it's a string
    try:
        datetime_obj = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f')
        return datetime_obj.strftime(format)
    except ValueError:
        return value  # Return the original value if it can't be formatted
    

def json_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a JSON file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_file, 'r') as f:
        config_data = json.load(f)
    return config_data


def yaml_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a YAML file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
    return config_data




def main(app):
    app.config['settings'] = {
        'FLASK_RUN_HOST': os.getenv('FLASK_RUN_HOST', '0.0.0.0'),
        'FLASK_RUN_PORT': os.getenv('FLASK_RUN_PORT', '80'),
        'FLASK_DEBUG': os.getenv('FLASK_DEBUG', 'True') == 'True',

        'API_TITLE': os.getenv('API_TITLE', 'KLMS Data API'),
        'API_VERSION': os.getenv('API_VERSION', '0.0.2'),
        'SPEC_FORMAT': os.getenv('API_SPEC_FORMAT', 'json'),

        'AUTO_SERVERS': os.getenv('API_AUTO_SERVERS', 'True') == 'True',
        'AUTO_TAGS': os.getenv('API_AUTO_TAGS', 'False') == 'True',
        'AUTO_OPERATION_SUMMARY': os.getenv('API_AUTO_OPERATION_SUMMARY', 'True') == 'True',
        'AUTO_OPERATION_DESCRIPTION': os.getenv('API_AUTO_OPERATION_DESCRIPTION', 'True') == 'True',

        'TAGS': json.loads(os.getenv('API_TAGS', '[{"name": "KLMS", "description": "Knowledge Lake Management System"}, {"name": "STELAR", "description": "Spatio-TEmporal Linked data tools for the AgRi-food data space"}]')),
        'DESCRIPTION': os.getenv('API_DESCRIPTION', 'Data API for managing resources in STELAR Knowledge Lake Management System'),
        'TERMS_OF_SERVICE': os.getenv('API_TERMS_OF_SERVICE', 'http://stelar-project.eu/'),
        'CONTACT': json.loads(os.getenv('API_CONTACT', '{"name": "API Support", "url": "<API-URL>", "email": "<CONTACT-EMAIL_ADDRESS>"}')),
        'LICENSE': json.loads(os.getenv('API_LICENSE', '{"name": "Apache 2.0", "url": "http://www.apache.org/licenses/LICENSE-2.0.html"}')),
        'SECURITY_SCHEMES': json.loads(os.getenv('API_SECURITY_SCHEMES', '{"ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "Api-Token"}}')),

        'CKAN_API': f"{os.getenv('CKAN_SITE_URL', 'http://<CKAN-HOST>')}/api/3/action/",
        'CKAN_ADMIN_TOKEN': os.getenv('CKAN_ADMIN_TOKEN', ''),

        'dbname': os.getenv('POSTGRES_DB', '<DB-NAME>'),
        'dbuser': os.getenv('POSTGRES_USER', '<DB-USERNAME>'),
        'dbpass': os.getenv('POSTGRES_PASSWORD', '<DB-PASSWORD>'),
        'dbhost': os.getenv('POSTGRES_HOST', '<DB-HOST>'),
        'dbport': os.getenv('POSTGRES_PORT', '5432'),

        'KEYCLOAK_URL': os.getenv('KEYCLOAK_URL', 'http://keycloak:8080'),
        'KEYCLOAK_CLIENT_ID': os.getenv('KEYCLOAK_CLIENT_ID', 'stelar'),
        'KEYCLOAK_CLIENT_SECRET': os.getenv('KEYCLOAK_CLIENT_SECRET', 'none'),
        'REALM_NAME': os.getenv('REALM_NAME','master'),

        'SPARQL_ENDPOINT': os.getenv('SPARQL_ENDPOINT', 'http://<ONTOP-HOST>/sparql'),

        'RANK_DEFAULT_TOPK': int(os.getenv('RANK_DEFAULT_TOPK', '10')),
        'RANK_MAX_TOPK': int(os.getenv('RANK_MAX_TOPK', '10000')),
        'RANK_AGG_ALGORITHM': os.getenv('RANK_AGG_ALGORITHM', 'Bordacount'),

        'API_URL': os.getenv('API_URL', 'http://stelarapi/'),

        'KLMS_DOMAIN_NAME' : os.getenv('KLMS_DOMAIN_NAME', 'stelar.gr'),
        'MAIN_INGRESS_SUBDOMAIN' : os.getenv('MAIN_INGRESS_SUBDOMAIN', 'klms'),
        'KEYCLOAK_SUBDOMAIN' : os.getenv('KEYCLOAK_SUBDOMAIN', 'kc'),
        'MINIO_API_SUBDOMAIN' : os.getenv('MINIO_API_SUBDOMAIN', 'minio'),

        'SMTP_SERVER' : os.getenv('SMTP_SERVER','stelar.gr'),
        'SMTP_PORT' : os.getenv('SMTP_PORT', '465'),
        'SMTP_EMAIL' : os.getenv('SMTP_EMAIL', 'info@stelar.gr'),
        'SMTP_PASSWORD' : os.getenv('SMTP_PASSWORD', 'None'),
        
        'execution': {
            'engine': os.getenv('EXECUTION_ENGINE') if 'EXECUTION_ENGINE' in os.environ else 'none'
        }
    }

    # Apply configuration settings for this API
    app.title = app.config['settings']['API_TITLE']
    app.version = app.config['settings']['API_VERSION']

    # Configure execution
    execution.configure(app.config["settings"])
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=1, x_host=1, x_port=1, x_prefix=1)
    # Execution of the application will happen from gunicorn after create_app returns the app instance    


# This entry point is used with gunicorn -b -w ....
def create_app():
    main(app)
    # Return the application instance so that gunicorn can run it.
    return app