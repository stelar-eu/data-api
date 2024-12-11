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



def create_task(json_data):
    # config = current_app.config['settings']
    if json_data['docker_image']:
        docker_image = json_data['docker_image']

    if json_data['tool_name']:
        tool_name = json_data['tool_name']

    workflow_exec_id = json_data['workflow_exec_id']
    docker_image = json_data['docker_image']
    # input_json = json_data['input_json']
    input = json_data['inputs']
    parameters = json_data['parameters']
    datasets = json_data['datasets']

    try :
        #### CHECK WORKFLOW EXECUTION STATE
        # status = check_workflow_status(workflow_exec_id)
        state = sql_utils.workflow_execution_read(workflow_exec_id)['state']
        if state != 'running':
            return jsonify({'success': False, 'message': 'This workflow no longer accepts tasks'}), 500 
         
        #### UPDATE KG
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = 'running'
        task_exec_id = str(uuid.uuid4())
        
        response = sql_utils.task_execution_create(task_exec_id, workflow_exec_id, start_date, state, datasets)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500
        # response = task_execution_insert_input(task_exec_id, input_json.get('input', []))
        response = sql_utils.task_execution_insert_input(task_exec_id, input)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500        
        # response = task_execution_insert_parameters(task_exec_id, input_json.get('parameters', {}))
        parameters = {k: str(v) for k, v in parameters.items()}
        response = sql_utils.task_execution_insert_parameters(task_exec_id, parameters)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500

        engine = execution.exec_engine()
        tags['container_id'], tags['job_id'] = engine.create_task(docker_image, request.headers.get('Authorization'), task_exec_id)

        tags['package_id'] = package_id
        tags['tool_image'] = docker_image
        response = sql_utils.task_execution_update(task_exec_id, state, tags=tags)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500

        
        return jsonify({'success': True, 'task_exec_id': task_exec_id, 'job_id': tags['job_id']}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

        pass
    except:
        pass