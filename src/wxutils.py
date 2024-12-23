import requests
from flask import current_app,jsonify
import re
import json
import utils
from urllib.parse import urljoin, urlencode
import sql_utils
import uuid
from routes.users import api_user_editor
from datetime import datetime
import execution
import kutils
import cutils
import xml.etree.ElementTree as ET

import logging
logging.basicConfig(level=logging.DEBUG)

def is_valid_url(url):
    pattern = re.compile(
        r'^(s3|https|http|tcp|smb|ftp)://[a-zA-Z0-9.-]+(?:/[^\s]*)?$'
    )
    return bool(pattern.match(url))


def is_valid_uuid(s):
    try:
        # Try converting the string to a UUID object
        uuid_obj = uuid.UUID(s)
        # Check if the string matches the canonical form of the UUID (with lowercase hexadecimal and hyphens)
        return str(uuid_obj) == s
    except ValueError:
        return False


def api_artifact_id(resource_id):
    """Get the file path of an artifact, given its resource ID.

    Provides the path to the file (URL, S3 bucket or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    config = current_app.config['settings']

  
    package_headers, resource_headers = utils.create_CKAN_headers(config['CKAN_ADMIN_TOKEN'])
 
    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+resource_id, headers=package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    # Get the path of this artifact 
    if response.status_code == 200:
        return response.json()['result']['url']
    else:
        return None


def create_workflow_process(creator_user, package_id, tags):
    """Create a new workflow process.

    Creates a new workflow process based on the input parameters provided. The workflow process is used to manage 
    and monitor the execution of tasks. The workflow process is associated with a package in CKAN and can have additional metadata.
    The workflow acts as a shared context for the tasks belonging to it.


    Args:
        creator_user: The username of the user who creates the workflow process.
        package_id: The unique identifier of the package associated with the workflow.
        tags: Additional metadata associated with the workflow process.

    Returns:
        The unique identifiers of the created workflow process and its linked package.
    """
    try :
        workflow_exec_id = str(uuid.uuid4())
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = 'running'
        tags['package_id'] = package_id

        response = sql_utils.workflow_execution_create(workflow_exec_id, start_date, state, creator_user, package_id, tags)
        if not response:
            return None
        return workflow_exec_id
    
    except Exception as e:
        raise RuntimeError(f"Workflow could not be created. {e}")

def create_task(json_data, token):
    """Create a new task execution.
    
       Creates a new task execution based on the input JSON provided. The task execution is associated with a workflow execution 
       which is used to monitor the progress of the tasks belonging to it and acting as a shared context for the tasks.

       Args:
              json_data: The input JSON for the task execution.
              token: The access token for the user.
       Returns:
              A JSON with the task execution ID and the job ID (if the task is executed in the cluster).
    """
    try:
        userinfo = kutils.get_user_by_token(token)
        creator_user_id = userinfo.get('preferred_username',None)
    except Exception as e:
        raise ValueError

    try:
        tags = {}

        workflow_exec_id = json_data['workflow_exec_id']
        input = json_data.get('inputs')
        parameters = json_data.get('parameters')
        datasets = json_data.get('datasets')
        

        #### CHECK WORKFLOW EXECUTION STATE AND EXISTENCE
        workflow = sql_utils.workflow_execution_read(workflow_exec_id)
        if workflow is None:
            raise RuntimeError("Workflow does not exist!")
        
        if workflow.get('state') != 'running':
            raise AttributeError("Workflow is committed and will not accept tasks!")
            
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = 'running'
        task_exec_id = str(uuid.uuid4())
        
        response = sql_utils.task_execution_create(task_exec_id, workflow_exec_id, start_date, state, creator_user_id)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500

        for key in input:
            resources = []
            input_group_name = key
            for val in input[key]:
                dataset_uuid, filter_value = None, None
                # Extract possible filter from val
                if "::" in val:
                    dataset_uuid, filter_value = val.split("::", 1)

                # Check if the value is a valid UUID
                if is_valid_uuid(dataset_uuid or val):
                    if cutils.is_package(dataset_uuid or val):
                        # Pass dataset_uuid and filter_value to get_package_resources
                        dataset_resources = [
                            resource['id'] for resource in cutils.get_package_resources(dataset_uuid or val, filter_value)
                        ]

                        resources.extend(dataset_resources)
                    elif cutils.is_resource(dataset_uuid or val):
                        resources.append(dataset_uuid or val)
                elif is_valid_url(val):
                    resources.append(val)

            logging.debug(f"inserting {key}: {resources}")
            response = sql_utils.task_execution_insert_input(task_exec_id, resources, input_group_name)

        if not response:
            raise RuntimeError("Task could not be created due to a database error.")
        
        parameters = {k: str(v) for k, v in parameters.items()}
        response = sql_utils.task_execution_insert_parameters(task_exec_id, parameters)
        
        if not response:
            raise RuntimeError("Task could not be created due to a database error regarding parameters.")

        # Task can also be executed outside the cluster, in that case image was specified so we create
        # a job conditionally.

        # Check if 'docker image' or 'tool name' fields exists inside json_data
        if json_data.get('tool_name'):
            tags['tool_name'] = json_data.get('tool_name', None)
            
        if json_data.get('docker_image'):
            engine = execution.exec_engine()
            token = 'Bearer ' + token
            tags['container_id'], tags['job_id'] = engine.create_task(json_data.get('docker_image'), token, task_exec_id)
            tags['tool_image'] = json_data.get('docker_image')
        
        response = sql_utils.task_execution_update(task_exec_id, state, tags=tags)
        if not response:
            raise RuntimeError("Task could not be created due to an execution engine error.")

        return {'task_exec_id': task_exec_id, 'job_id': tags.get('job_id','Remote Task Mode')}
    except Exception as e:
        raise RuntimeError(f"Task could not be created. {e}")


def get_task_metadata(task_id):
    """Retrieve the metadata for a task execution.
    
       Provides the metadata for a task execution, including the state, start and end time, and the tags. 
       The metadata is used to monitor the progress of a task execution.

       Args:
              task_id: The unique identifier of the task execution.
       Returns:
              A JSON with the metadata for the specified task id.
    """

    try :
        d = dict()

        t = sql_utils.task_execution_read(task_id)
        if t:
            d.update(sql_utils.task_execution_read(task_id))

            if d['tags'].get('tool_image'):
                d['tool_image'] = d['tags']['tool_image']

            if d['tags'].get('tool_name'):
                d['tool_name'] = d['tags']['tool_name']

            state = d['state']

            if state != 'failed' and state != 'succeeded':
                return d
            
            d['messages'] = d['tags']['log']
            
            d['output'] = sql_utils.task_execution_output_read(task_id)
            d['metrics'] = sql_utils.task_execution_metrics_read(task_id)

            return d            
        else:
            raise ValueError("Task does not exist.")
    except ValueError as e:
        raise
    except Exception as e:
        raise RuntimeError(f"Task Metadata Could Not Be Retrieved. {e}")

    


def get_task_logs(task_id):
    pass


def get_task_input_json(task_id, access_token=None):
    """Retrieve the input JSON for a task execution. This is the JSON the tool finally receives.

       Provides the input JSON for a task execution, including the input groups and the parameters. The input JSON is used to create a task execution.

       Args:
              task_id: The unique identifier of the task execution.
              access_token: The access token for MinIO. (Default is None)
       Returns:
              A JSON with the input groups, parameters and MinIO credentials (if access_token was provided and was valid) for the specified task id.
    """
    if is_valid_uuid(task_id):
        task_exec_id = task_id
        config = current_app.config['settings']
        
        # Check if the task exists
        try:
            get_task_metadata(task_exec_id)
        except ValueError as e:
            raise ValueError("Task does not exist.")

        # Fetch the input groups and the parameters for the task execution from the database
        input = sql_utils.task_execution_input_read_sql(task_exec_id)
        parameters = sql_utils.task_execution_parameters_read(task_exec_id)

        if access_token:
            # Produce STS Token for MinIO Access 
            minio_body = {      
                'Action':'AssumeRoleWithWebIdentity',
                'WebIdentityToken': access_token, 
                'Version' : '2011-06-15',
                'DurationSeconds' : '86000'
            }
            minio_url = "https://"+config['MINIO_API_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']

            # Make a POST request to MinIO's STS endpoint to retrieve credentials, if any.
            try:
                response = requests.post(
                    url=minio_url, 
                    params=minio_body,
                    verify=False
                )
            except requests.exceptions.RequestException:
                pass

            # Handle the response, parse XML if successful
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    # Extracting relevant information from the XML
                    credentials = root.find('.//{https://sts.amazonaws.com/doc/2011-06-15/}Credentials')
                    if credentials is not None:
                        access_key = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId') is not None else None
                        secret_key = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey') is not None else None
                        session_token = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken') is not None else None
                except ET.ParseError as e:
                    pass
                    
        try :
            # Fetch the URL/Path pointed by each artifact in the inputs spec (or pass it as plain path) 
            input_paths = dict()
            # We allow grouping of inputs in the JSON tool spec. For each group, we fetch the paths of the artifacts or URLs.
            for group in input:
                # We maintain a list of paths for each group(field) into a dictionary
                input_paths[group] = list()
                for artifact in input[group]:
                    # If the artifact is a URL, we directly append it to the list, else we fetch the path from CKAN
                    if is_valid_uuid(artifact):
                        artifact = api_artifact_id(artifact)
                        if artifact is None:
                            continue
                    input_paths[group].append(artifact)

            # Check if credentials are not None, else we return the input paths and parameters only.
            if access_key and secret_key and session_token:
                result = {
                    'input': input_paths,
                    'parameters': parameters, 
                    'minio': {
                        'endpoint_url': minio_url,
                        'id': access_key,
                        'key': secret_key,
                        'skey': session_token
                    },
                    # This should be populated in a later stage.
                    'output':{}
                }
            else:
                result = {
                    'input': input_paths, 
                    'parameters': parameters,  
                    'output':{}
                }
                
            return result
        
        except Exception as e:
            raise RuntimeError(f"Task Input Could Not Be Retrieved. {e}")
    else:
        raise AttributeError("Invalid Task ID provided.")

