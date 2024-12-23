from flask import request, jsonify, current_app
from apiflask import APIBlueprint, HTTPTokenAuth
import requests
import json
import sql_utils
import re
import uuid
import traceback
from routes.users import api_user_editor
from src.auth import auth, security_doc, token_active
from datetime import datetime
import xml.etree.ElementTree as ET

from demo_t import get_demo_ckan_token


#from container_utils import create_container
import execution

# Auxiliary custom functions & SQL query templates for ranking
import utils

# Input schema for validating and structuring several API requests
import schema


"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to the lifecycle of
    tasks in the ecosystem of the KLMS.
"""


# The tasks operations blueprint for all operations related to the lifecycle of `tasks
tasks_bp = APIBlueprint('tasks_blueprint', __name__,tag='Tracking Operations')



def api_artifact_id(resource_id, headers):
    """Get the file path of an artifact. 

    Provides the path to the file (URL, S3 bucket or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    config = current_app.config['settings']

    if headers:
        package_headers, resource_headers = utils.create_CKAN_headers(get_demo_ckan_token())
    else:
        return None

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+resource_id, headers=package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    # Get the path of this artifact 
    if response.status_code == 200:
        return response.json()['result']['url']
    else:
        return None


def api_artifact_publish(json_data, headers):
    """Publish an artifact created by a workflow execution.

    If a package id is provided, associate the artifact (with its URL) to this package in CKAN. Otherwise, create a new package in CKAN to make this association. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new artifact.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    config = current_app.config['settings']

    if headers:
        if headers:
            package_headers, resource_headers = utils.create_CKAN_headers(get_demo_ckan_token())
        else:
            return {'success':False, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
    else:
        return {'success':False,  'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}

    specs = json_data

    if specs.get('artifact_metadata') != None:
        artifact_metadata = specs['artifact_metadata']
    else:
        return {'success':False, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this artifact in the Catalog. Please specify metadata for the artifact you wish to publish.']}}

    # Check if a new package needs to be created with the basic metadata
    if specs.get('package_metadata') != None:
        package_metadata = specs['package_metadata']
        if package_metadata.get('package_id') != None:
            # Make a POST request to the CKAN API to associate this artifact to an existing dataset (CKAN package)
            artifact_metadata['package_id'] = package_metadata['package_id']
            resp_resource = requests.post(config['CKAN_API']+'resource_create', data=artifact_metadata, headers=resource_headers)
            result = {'package_id': artifact_metadata['package_id']}
            if resp_resource.status_code == 200:
                resource_id = resp_resource.json()['result']['id']
                result['resource_id'] = resource_id
#                print("resource_id: ", resource_id)
            else:
                return resp_resource.json()
            response = {'success':True,  'result':result} 
            return response
        else:
        # Register a new package with some basic metadata
            arr_resp = []
            # Also create the name of the new CKAN package from its title (assuming that this is unique)
            package_metadata['name'] = re.sub(r'[\W_]+','_',package_metadata['title']).lower()
            # Internal call to find the organization where the user belongs to (derived from API token)
            resp_org = api_user_editor()
            if resp_org['success']:
                org_json = resp_org['result']
                if len(org_json) > 0:  
                    for item in org_json: 
                        if item['type'] == 'organization' and item['state'] == 'active' and item['capacity'] in ('admin','editor'):
                            package_metadata['owner_org'] = org_json[0]['name']  # CAUTION! Taking the first organization where this user is editor
                            break

            # Make a POST request to the CKAN API with the basic metadata
            resp_basic = requests.post(config['CKAN_API']+'package_create', json=package_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
            arr_resp.append(resp_basic.json())

            result = {}
            # Get the id of the newly created package in order to associate the artifact as a resource
            if resp_basic.status_code == 200:
                package_id = resp_basic.json()['result']['id']
                result['package_id'] = package_id
#                print("package_id: ", package_id)
            else:
                return resp_basic.json()

            artifact_metadata['package_id'] = package_id
            # Make a POST request to the CKAN API to link the artifact as a resource
            resp_resource = requests.post(config['CKAN_API']+'resource_create', data=artifact_metadata, headers=resource_headers)
            arr_resp.append(resp_resource.json())

            if resp_resource.status_code == 200:
                resource_id = resp_resource.json()['result']['id']
                result['resource_id'] = resource_id
#                print("resource_id: ", resource_id)
            else:
                return resp_resource.json()

            # Examine collected responses to compose the overall response
            success = True   
            for idx, resp in enumerate(arr_resp):
                success &= resp['success']
#                result.append(resp)

            response = {'success':success, 'result':result}     
            return response


############################## TASK OPERATIONS ################################


@tasks_bp.route('/execution/input_json', methods=['GET'])
@tasks_bp.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
@tasks_bp.doc(tags=['Tracking Operations'], security=security_doc)
@token_active
def api_task_execution_input_json(query_data):
    """Return the input json of the specific Task Execution.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the input fields.
    """
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/execution/input_json?id=24a976c4-fd84-47ef-92cc-5d5582bcaf41

    task_exec_id = query_data['id']
    
    config = current_app.config['settings']
    # input = json_data['input']
    input = sql_utils.task_execution_input_read_sql(task_exec_id)
    print(input)
    # parameters = json_data['parameters']
    parameters = sql_utils.task_execution_parameters_read(task_exec_id)


    if request.headers:
        if not request.headers['Authorization'] is None:
            access_token = request.headers['Authorization'].replace("Bearer ","")
        else:
            return {'success':False, 'error':{'__type':'Authorization Error','name':['No Access Token specified. Please specify a valid Authorization Bearer token in the headers of your request.']}}


    # Produce STS Token for MinIO Access 
    minio_body = {      
        'Action':'AssumeRoleWithWebIdentity',
        'WebIdentityToken': access_token, 
        'Version' : '2011-06-15',
        'DurationSeconds' : '86000'
    }
    minio_url = "https://"+config['MINIO_API_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']

    # Properly make a POST request to MinIO's STS endpoint
    response = requests.post(
        url=minio_url, 
        params=minio_body,
        verify=False
    )

        # Handle the response, parse XML if successful
    if response.status_code == 200:
        try:
            # Parse the XML response
            root = ET.fromstring(response.text)
            
            # Extracting relevant information from the XML
            credentials = root.find('.//{https://sts.amazonaws.com/doc/2011-06-15/}Credentials')
            if credentials is not None:
                access_key = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId') is not None else None
                secret_key = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey') is not None else None
                session_token = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken') is not None else None
        except ET.ParseError as e:
            print("Failed to parse XML:", e)
    else:
        print("Failed to get STS Token:", response.status_code, response.text)
    
    
    
    try :
        #### GET FILE PATHS BY LOOKING INTO THE DATABASE
        input_paths = dict()
        for group in input:
            input_paths[group] = list()
            for artifact in input[group]:
                if sql_utils.is_valid_uuid(artifact):
                    artifact = api_artifact_id(artifact, headers=request.headers)
                    if artifact is None:
                        return jsonify({'success': False, 'message': f'This resource {artifact} cannot be fetched by CKAN'}), 500 
                input_paths[group].append(artifact)

        # # Check if all required values are not None
        if access_key and secret_key and session_token:
            # Constructing the JSON
            result = {
                'input': input_paths,  # Assuming `input_paths` is defined
                'parameters': parameters,  # Assuming `parameters` is defined
                'minio': {
                    'endpoint_url': minio_url,
                    'id': access_key,
                    'key': secret_key,
                    'skey': session_token
                }
            }
            # Printing or using the constructed JSON
            print(result)
        else:
            print("One or more values required for JSON construction are missing.")
            
        return jsonify({'success': True, 'result': result}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



@tasks_bp.route('/execution/output_json', methods=['POST'])
@tasks_bp.input(schema.Task_Output, location='json', example={"task_exec_id": "4a142419-2342-4495-bfa3-9b4b3c2cad2a",
                                                        "output_json": {
                                                                "message": "Tool executed successfully!",
                                                                "output": [{
                                                                    "path": "s3://XXXXXXXXX-bucket/2824af95-1467-4b0b-b12a-21eba4c3ac0f.csv",
                                                                    "name": "List of joined entities"
                                                                    }
                                                                ],
                                                                "metrics": {
                                                                    "metric": 0.90,
                                                                },
                                                                "status": 200
                                                            }})
# @tasks_bp.output(schema.ResponseOK, status_code=200)
@tasks_bp.doc(tags=['Tracking Operations'], security=security_doc)
@token_active
def api_task_execution_output_json(json_data):
    """Receives the output json of a task execution, it marks it as done, it stores
    all the information to the KG and it returns the metrics and output files 
    in the Data Catalog.

    Args:
        id: The unique identifier of the Task Exection.
        output_json: The json that the tool has produced.

    Returns:
        A JSON with the task execution metadata, the metrics and the ids of the 
        outputfiles in the Data Catalog.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/execution/track -d '{"task_exec_id": "4a142419-2342-4495-bfa3-9b4b3c2cad2a", "output_json": {"message": "Tool executed successfully!", "output": [{ "path": "s3://XXXXXXXXX-bucket/2824af95-1467-4b0b-b12a-21eba4c3ac0f.csv","name": "List of joined entities"}], "metrics": {"metric": 0.90},"status": 200}}'

    task_exec_id = json_data['task_exec_id']
    output_json = json_data['output_json']
    print(output_json)
    
    try :
        #### GET METADATA FROM KG
        metadata = sql_utils.task_execution_read(task_exec_id)
        container_id = metadata['tags']['container_id']
        package_id = metadata['tags']['package_id']
        
        print(task_exec_id)
        print(container_id)
        print(metadata)
        
        
        if output_json['status'] == 200:
            state = 'succeeded'
        else:
            state = 'failed'
        
        metadata['state'] = state

    
        #### UPDATE TASK EXECUTION
        end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        response = sql_utils.task_execution_update(task_exec_id, state, end_date)
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        #### INSERT METRICS
        metrics = output_json.get('metrics', {})
        metrics = {k: str(v) for k, v in metrics.items()}
        response = sql_utils.task_execution_insert_metrics(task_exec_id, metrics)
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        #### INSERT LOG
        response = sql_utils.task_execution_insert_log(task_exec_id, output_json.get('message', ""))
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        #### INSERT FILES TO CATALOG
        output_resource_ids = []
        for file in output_json['output']:
            ftype = file['path'].split('/')[-1].split(".")[-1].upper()
            d = { "artifact_metadata":{
                        "url":file['path'],
                        'name': file['name'],
                        "description": file['name'] + f'({ datetime.now().strftime("%Y-%m-%d %H:%M:%S")})',
                        "format": ftype,
                        "resource_tags":["Artifact"]
                        },
                    "package_metadata":  {
                        "package_id": package_id
                        }
                }
    
            response = api_artifact_publish(d, headers=request.headers)
            print(response)
            if response['success']:
                output_resource_ids.append(response['result']['resource_id'])
            else:
                return jsonify({'success': False, 'message': 'Error in publishing in CKAN'}), 500 
            
        #### INSERT OUTPUT FILES
        response = sql_utils.task_execution_insert_output(task_exec_id, output_resource_ids)
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        return jsonify({'success': True, 'resource_ids': output_resource_ids,
                        'metrics': metrics}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': traceback.format_exc()}), 500  



@tasks_bp.route('/execution/read', methods=['GET'])
@tasks_bp.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
# @tasks_bp.output(schema.ResponseOK, status_code=200)
@tasks_bp.doc(tags=['Tracking Operations'], security=security_doc)
@token_active
def api_task_execution_read(query_data):
    """Return the metadata of the task execution.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the task execution metadata.
    """
    
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/execution/read?id=24a976c4-fd84-47ef-92cc-5d5582bcaf41

    task_exec_id = query_data['id']
    
    try :
        #### GET METADATA FROM KG
        d = {}
        d['metadata'] = sql_utils.task_execution_read(task_exec_id)
        state = d['metadata']['state']
        if state != 'failed' and state != 'succeeded':
            return jsonify({'success': True, 'result': d}), 200    
        d['output'] = sql_utils.task_execution_output_read(task_exec_id)
        d['metrics'] = sql_utils.task_execution_metrics_read(task_exec_id)
            
        return jsonify({'success': True, 'result': d}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': traceback.format_exc()}), 500  


@tasks_bp.route('/read/logs', methods=['GET'])
@tasks_bp.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
@tasks_bp.doc(tags=['Tracking Operations'], security=security_doc)
@token_active
def api_task_log_read(query_data):
    """Return the log of a task executed in the cluster.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the logs of all attempted executions logs.
    """
    
    task_exec_id = query_data['id']
    
    try :
        engine = execution.exec_engine()
        logs = engine.fetch_task_logs(task_id=task_exec_id)
            
        return logs
    except Exception as e:
        return jsonify({'success': False, 'message': traceback.format_exc()}), 500  
    

@tasks_bp.route('/runtime/read', methods=['GET'])
@tasks_bp.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
# @tasks_bp.output(schema.ResponseOK, status_code=200)
@tasks_bp.doc(tags=['Tracking Operations'], security=security_doc)
def api_task_runtime_read(query_data):
    """Return the runtime information of a task executed in the cluster.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the runtime information of the pod executing the task
    """
    
    task_exec_id = query_data['id']
    
    try :
        engine = execution.exec_engine()
        info = engine.get_task_info(task_id=task_exec_id)
        return jsonify(info)
    
    except Exception as e:
        return jsonify({'success': False, 'message': traceback.format_exc()}), 500  


@tasks_bp.route('/execution/delete', methods=['GET'])
@tasks_bp.input(schema.Identifier, location='query', example="4a142419-2342-4495-bfa3-9b4b3c2cad2a")
# @tasks_bp.output(schema.ResponseOK, status_code=200)
@tasks_bp.doc(tags=['Tracking Operations'], security=security_doc)
@token_active
def api_task_execution_delete(query_data):
    """Delete the given Task Execution id.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the corresponding message.
    """
    
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/execution/delete?id=4a142419-2342-4495-bfa3-9b4b3c2cad2a

    # task_exec_id = request.args.id
    task_exec_id = query_data['id']
    try :
        response = sql_utils.task_execution_delete(task_exec_id)
        if not response:
            return jsonify({'success': True, 'message': f'The Task {task_exec_id} could not be deleted.'}), 500
        return jsonify({'success': True, 'message': f'The Task {task_exec_id} was deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': True, 'message': str(e)}), 500