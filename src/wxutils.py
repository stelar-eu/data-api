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


def create_task(json_data, token):

    # retrieve creator's user id from the access token
    # access_token = req_headers.get('Authorization').split(" ")[1]
    # kopenid = kutils.initialize_keycloak_openid()
    # userinfo = kopenid.introspect(access_token)
    # creator_user_id = userinfo.get('preferred_username')

    
    try:
        userinfo = kutils.get_user_by_token(token)
        creator_user_id = userinfo.get('preferred_username',None)
    except Exception as e:
        raise ValueError

    tags = {}
    # Check if 'docker image' or 'tool name' fields exists inside json_data
    if json_data.get('docker_image'):
        docker_image = json_data.get('docker_image', None)

    if json_data.get('tool_name'):
        tags['tool_name'] = json_data.get('tool_name', None)

    workflow_exec_id = json_data['workflow_exec_id']
    input = json_data.get('inputs')
    parameters = json_data.get('parameters')
    datasets = json_data.get('datasets')
    

    try :
        #### CHECK WORKFLOW EXECUTION STATE
        state = sql_utils.workflow_execution_read(workflow_exec_id)['state']
        if state != 'running':
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
                # Initialize dataset_uuid and filter
                dataset_uuid, filter = None, None
                # Extract possible filter from val
                if "::" in val:
                    dataset_uuid, filter = val.split("::", 1)

                if is_valid_uuid(dataset_uuid or val):
                    if cutils.is_package(dataset_uuid or val):
                        # Pass dataset_uuid and filter_ to get_package_resources
                        dataset_resources = []
                        dataset_resources = [resource['id'] for resource in cutils.get_package_resources(dataset_uuid or val, filter)]
                        # Merge the arrays
                        resources = resources + dataset_resources
                elif is_valid_uuid(val):
                    if cutils.is_resource(val):
                        resources.append(val)
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
        if docker_image is not None:
            engine = execution.exec_engine()        
            tags['container_id'], tags['job_id'] = engine.create_task(docker_image, token, task_exec_id)
            tags['tool_image'] = docker_image
            response = sql_utils.task_execution_update(task_exec_id, state, tags=tags)
            if not response:
                raise RuntimeError("Task could not be created due to an execution engine error.")

        return {'task_exec_id': task_exec_id, 'job_id': tags.get('job_id','Remote Task Mode')}
    
    except Exception as e:
        raise RuntimeError(f"Task could not be created. Please validate your input. {e}")