import requests
import json

from flask import current_app
# Auxiliary custom functions & SQL query templates for ranking
import utils
import ast
import pandas as pd
import uuid


def is_valid_uuid(s):
    try:
        # Try converting the string to a UUID object
        uuid_obj = uuid.UUID(s)
        # Check if the string matches the canonical form of the UUID (with lowercase hexadecimal and hyphens)
        return str(uuid_obj) == s
    except ValueError:
        return False
    
def cast_dict(d):
    d2 = {}
    for key, value in d.items():
        try:
            d2[key] = ast.literal_eval(value)
        except:
            d2[key] = value
    return d2

def convert_datatype(df):
    df2 = df.copy()
    for column in df.columns:
        x = df[column][0]
        try:
            dtype = type(ast.literal_eval(x))
            df2[column] = df[column].astype(dtype)
        except (ValueError, TypeError):
            df2[column] = df[column].astype(str)
                
    return df2

'''
def cast_dict(d):
    d2 = {}
    for key, value in d.items():
        try:
            # Try converting the value to an integer first
            d2[key] = int(value)
        except ValueError:
            try:
                # If it's not possible to convert to an integer, try converting to a float
                d2[key] = float(value)
            except ValueError:
                # If both conversions fail, leave the value unchanged
                d2[key] = value

    return d2
'''

def policy_version_create(policy_uuid, policy_familiar_name, active, yaml_content, user_id) -> str:
    """Records in the database that the user-specified parameters for the given policy 

    Args:
        policy_uuid: UUID of the policy_version
        parameters: A JSON dictionary with parametrization as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution 
    sql = utils.sql_policy_template['policy_create_template']   
    resp = utils.execSql(sql, (policy_uuid, policy_familiar_name, active, yaml_content, user_id))
    if 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False
    
    return True

def list_policies():
    sql = utils.sql_policy_template['policy_get_all_info_template']
    resp = utils.execSql(sql)
    if resp and len(resp)>0:
        policies = resp
        return policies
    else:
        return None
   
        
def policy_representation_read(filter):
    if is_valid_uuid(filter):
        sql = utils.sql_policy_template['policy_get_yaml_by_id_template']
        resp = utils.execSql(sql,(filter, ))
        if resp and len(resp)>0:
            policy_version = resp[0]
            return policy_version['yaml_content']
        else:
            return None
    elif filter == 'active':
        sql = utils.sql_policy_template['policy_get_yaml_by_state_template']
        resp = utils.execSql(sql,(True, ))
        if resp and len(resp)>0:
            policy_version = resp[0]
            
            return policy_version['yaml_content']
        else:
            return None
        
def policy_info_read(filter):
    if is_valid_uuid(filter):
        sql = utils.sql_policy_template['policy_get_info_by_id_template']
        resp = utils.execSql(sql,(filter, ))
        if resp and len(resp)>0:
            policy_version = resp[0]
            return policy_version
        else:
            return None
    elif filter == 'active':
        sql = utils.sql_policy_template['policy_get_info_by_state_template']
        resp = utils.execSql(sql,(True, ))
        if resp and len(resp)>0:
            policy_version = resp[0]
            return policy_version
        else:
            return None
    


def workflow_execution_create(workflow_exec_id, start_date, state, tags=None):
    """Records metadata for a new workflow execution in the database.

    Args:
        workflow_exec_id: UUID of the new workflow execution.
        start_date: Start timestamp of the new workflow execution.
        state: Initial state of the new workflow execution.
        tags: A JSON dictionary with workflow execution metadata as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for creating a new workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_create_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (workflow_exec_id, state, start_date))
    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False
        

    # Compose the SQL command using the template for assigning tags to the new workflow execution 
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates['workflow_insert_tags_template']   

            # Execute the SQL command in the database
            resp = utils.execSql(sql, (workflow_exec_id, key, value))
            if resp and 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def workflow_execution_update(workflow_exec_id, state, end_date=None):
    """Updates metadata regarding a workflow execution in the database.

    Args:
        task_exec_id: UUID of a workflow execution.
        state: Current state of this workflow execution.
        end_date: Timestamp marking the end of this workflow execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose and execute the SQL command using the template for updating/commiting a workflow execution
    if not end_date is None:
        sql = utils.sql_workflow_execution_templates['workflow_commit_template']  
        resp = utils.execSql(sql, (state, end_date, workflow_exec_id))
    else:
        sql = utils.sql_workflow_execution_templates['workflow_update_template']  
        resp = utils.execSql(sql, (state, workflow_exec_id))

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True


def workflow_execution_delete(workflow_exec_id):
    """Deletes all metadata regarding a workflow execution from the database. CAUTION! This also includes all metadata about task executions associated with this workflow execution.

    Args:
        workflow_exec_id: UUID of a workflow execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for deleting a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_delete_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (workflow_exec_id, ))

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True


def workflow_execution_read(workflow_exec_id):
    """Returns metadata recorded in the database about the given workflow execution. User-specified tags are included in the returned response.

    Args:
        task_exec_id: UUID of the workflow execution.

    Returns:
        A JSON with the workflow execution metadata.
    """

    # Compose the SQL command using the template for reading metadata about a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_read_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (workflow_exec_id, ))

    if resp and len(resp)>0:
        workflow_specs = resp[0]  # List should contain specification of a single workflow execution (unique UUID)
        # Also include any user-specified tags in the response
        workflow_specs['tags'] = workflow_execution_tags_read(workflow_exec_id)
        return workflow_specs
    else:
        return None


def workflow_execution_tags_read(workflow_exec_id):
    """Returns tags recorded as (key, value) pairs in the database about the given workflow execution.

    Args:
        workflow_exec_id: UUID of the workflow execution.

    Returns:
        A JSON dictionary with the workflow execution tags.
    """

    # Compose the SQL command using the template for reading tags about a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_read_tags_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (workflow_exec_id, ))

    if resp and len(resp)>0:
        tag_dict = {tag['key']: tag['value'] for tag in resp}
        return tag_dict
    else:
        return None



def task_execution_create(task_exec_id, workflow_exec_id, start_date, state, tags=None, prev_task_exec_id=None):
    """Records metadata for a new task execution in the database.

    Args:
        workflow_exec_id: UUID of an existing workflow execution.
        task_exec_id: UUID of the new task execution.
        start_date: Start timestamp of the new task execution.
        state: Initial state of the new task execution.
        tags: A JSON dictionary with task execution metadata as (key, value) pairs.
        prev_task_exec_id: UUID of the exexcution of the previous task in the workflow pipeline.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for creating a new task execution
    sql = utils.sql_workflow_execution_templates['task_create_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (task_exec_id, workflow_exec_id, state, start_date))
    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    # Compose the SQL command using the template for specifying the previously executed task
    if prev_task_exec_id:
        sql = utils.sql_workflow_execution_templates['task_create_connection_template']   

        # Execute the SQL command in the database
        resp = utils.execSql(sql, (task_exec_id, prev_task_exec_id))
        if resp and 'status' in resp:
            if not resp.get('status'):
                return False
        else:
            return False

    # Compose the SQL command using the template for assigning tags to the new task execution 
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates['task_insert_tags_template']   

            # Execute the SQL command in the database
            resp = utils.execSql(sql, (task_exec_id, key, value))
            if resp and 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def task_execution_update(task_exec_id, state, end_date=None, tags=None):
    """Updates metadata regarding a task execution in the database.

    Args:
        task_exec_id: UUID of a task execution.
        state: Current state of this task execution.
        end_date: Timestamp marking the end of this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose and execute the SQL command using the template for updating a task execution
    if not end_date is None:
        sql = utils.sql_workflow_execution_templates['task_commit_template']  
        resp = utils.execSql(sql, (state, end_date, task_exec_id))
    else:
        sql = utils.sql_workflow_execution_templates['task_update_template']  
        resp = utils.execSql(sql, (state, task_exec_id))

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False
    
    # Compose the SQL command using the template for assigning tags to the new task execution 
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates['task_insert_tags_template']   

            # Execute the SQL command in the database
            resp = utils.execSql(sql, (task_exec_id, key, value))
            if resp and 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def task_execution_delete(task_exec_id):
    """Deletes all metadata regarding a task execution from the database. CAUTION! This also includes all tags, parameters, and metrics associated with this task execution.

    Args:
        task_exec_id: UUID of a task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for deleting a task execution
    sql = utils.sql_workflow_execution_templates['task_delete_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (task_exec_id, ))

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True



def task_execution_insert_log(task_exec_id, log):
    """Records the log of a task execution in the database.

    Args:
        task_exec_id: UUID of the task execution.
        log: Text with the compiled logs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for inserting the log under tag "log" for this task execution 
    sql = utils.sql_workflow_execution_templates['task_insert_tags_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (task_exec_id, 'log', log))
    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True



def task_execution_insert_input(task_exec_id, resource_ids):
    """Records in the database that the given dataset id was used as input in the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        resource_ids: Array of UUIDs of the dataset(s) (CKAN resources) used as input in this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording input datasets
    for idx, res_id in enumerate(resource_ids):
        sql = utils.sql_workflow_execution_templates['task_insert_input_dataset_template']   

        # Execute the SQL command in the database
        resp = utils.execSql(sql, (task_exec_id, idx, res_id))
        print(res_id, resp)
        if resp and 'status' in resp:
            if not resp.get('status'):
                return False
        else:
            return False

    return True


def task_execution_insert_output(task_exec_id, resource_ids):
    """Records in the database that the given dataset id was issued as output from the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        resource_ids: Array of UUIDs of the dataset(s) (i.e.,CKAN resources) issued as output from this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording output datasets
    for idx, res_id in enumerate(resource_ids):
        sql = utils.sql_workflow_execution_templates['task_insert_output_dataset_template']   

        # Execute the SQL command in the database
        resp = utils.execSql(sql, (task_exec_id, idx, res_id))
        if resp and 'status' in resp:
            if not resp.get('status'):
                return False
        else:
            return False

    return True


def task_execution_insert_parameters(task_exec_id, parameters):
    """Records in the database that the user-specified parameters for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        parameters: A JSON dictionary with the task execution parametrization as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution 
    if parameters:
        for key, value in parameters.items():
            sql = utils.sql_workflow_execution_templates['task_insert_parameters_template']   

            # Execute the SQL command in the database
            resp = utils.execSql(sql, (task_exec_id, key, value))
            if 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def task_execution_insert_metrics(task_exec_id, metrics):
    """Records in the database that the metrics collected for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        metrics: A JSON dictionary with the task execution metrics as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording metrics about a task execution 
    if metrics:
        for key, value in metrics.items():
            sql = utils.sql_workflow_execution_templates['task_insert_metrics_template']   

            # Execute the SQL command in the database
            resp = utils.execSql(sql, (task_exec_id, key, value))
            if 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True



def task_execution_read(task_exec_id):
    """Returns metadata recorded in the database about the given task execution. User-specified tags are included in the returned response.

    Args:
        task_exec_id: UUID of the task execution.

    Returns:
        A JSON with the task execution metadata.
    """

    # Compose the SQL command using the template for reading metadata about a task execution
    sql = utils.sql_workflow_execution_templates['task_read_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (task_exec_id, ))

    if resp and len(resp)>0:
        task_specs = resp[0]  # List should contain specification of a single task execution (unique UUID)
        # Also include any user-specified tags in the response
        task_specs['tags'] = task_execution_tags_read(task_exec_id)
        return task_specs
    else:
        return None


def task_execution_tags_read(task_exec_id):
    """Returns tags recorded as (key, value) pairs in the database about the given task execution.

    Args:
        task_exec_id: UUID of the task execution.

    Returns:
        A JSON dictionary with the task execution tags.
    """

    # Compose the SQL command using the template for reading tags about a task execution
    sql = utils.sql_workflow_execution_templates['task_read_tags_template']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (task_exec_id, ))

    if resp and len(resp)>0:
        tag_dict = {tag['key']: tag['value'] for tag in resp}
        return tag_dict
    else:
        return None
    
    
def task_execution_input_read(task_exec_id):
    """Submit a request to the Knowledge Graph to retrieve the identifiers of dataset(s) given as input to the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the list of dataset identifiers (CKAN resources) collected in MLFlow for the specified task execution.
    """

    config = current_app.config['settings']
    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_input_template', task_exec_id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    j = json.loads(response.text)
    print(j)
    res_ids = [res['resource_id']['value'] for res in j['results']['bindings']]
    
    # # Compose the SQL command using the template for reading tags about a task execution
    # sql = utils.sql_workflow_execution_templates['task_read_input_dataset_template']   

    # # Execute the SQL command in the database
    # resp = utils.execSql(sql, (task_exec_id, ))
    # print(resp)
    # if resp and len(resp)>0:
    #     res_ids = [res['dataset_id'] for res in resp]
    #     return res_ids
    # else:
    #     return None
    
    # print(res_ids)
    
    return res_ids


def task_execution_output_read(task_exec_id):
    """Submit a request to the Knowledge Graph to retrieve the identifiers of dataset(s) issued as output from the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the list of dataset identifiers (CKAN resources) collected as output in MLFlow for the specified task execution.
    """

    config = current_app.config['settings']

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_output_template', task_exec_id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    j = json.loads(response.text)
    res_ids = [res['resource_id']['value'] for res in j['results']['bindings']]

    # # Compose the SQL command using the template for reading tags about a task execution
    # sql = utils.sql_workflow_execution_templates['task_read_output_dataset_template']   

    # # Execute the SQL command in the database
    # resp = utils.execSql(sql, (task_exec_id, ))
    # if resp and len(resp)>0:
    #     res_ids = [res['dataset_id'] for res in resp]
    #     return res_ids
    # else:
    #     return None
    
    return res_ids


def task_execution_parameters_read(task_exec_id):
    """Submit a request to the Knowledge Graph retrieve the parameters specified for the task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the parameters specified in MLFlow for the specified task execution.
    """

    config = current_app.config['settings']

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_parameters_template', task_exec_id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    # return json.loads(response.text)
    j = json.loads(response.text)
    parameters = {res['parameter']['value']: res['value']['value'] for res in j['results']['bindings']}
    parameters = cast_dict(parameters)
    return parameters


def task_execution_metrics_read(task_exec_id):
    """Submit a request to the Knowledge Graph retrieve the metrics issued for the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the metrics collected in MLFlow for the specified task execution.
    """

    config = current_app.config['settings']

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_metrics_template', task_exec_id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    # return jsonify(json.loads(response.text))
    j = json.loads(response.text)
    metrics = {res['metric']['value']: res['value']['value'] for res in j['results']['bindings']}
    metrics = cast_dict(metrics)

    return metrics


def workflow_get_tasks(workflow_exec_id):
    """Submit a request to the Metadata Database to retrieve information about all tasks 
        belonging to a workflow execution with given id

    Args:
        id: The identifier (UUID) assigned to a worfklow execution

    Returns:
        A JSON with the tasks, if any, belonging to the workflow 
    """

    if workflow_exec_id:
          
        sql = utils.sql_workflow_execution_templates['workflow_get_tasks']   

        # Execute the SQL command in the database
        resp = utils.execSql(sql, (workflow_exec_id, ))

        if resp and len(resp)>0:
            wf_tasks = resp          
            return wf_tasks
        else:
            return None
        
def workflow_get_all():
    """
        Submit a request to the Metadata Database to retrieve information about all workflow
        executions. If an execution contains a reference to the package_id, it will be available 
        in the result.

    Returns:
        A JSON with the workflows, if any.
    """

    sql = utils.sql_workflow_execution_templates['workflow_get_all']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql)

    if resp and len(resp)>0:
        wf_tasks = resp          
        return wf_tasks
    else:
        return None




def workflow_statistics(workflow_tags, parameters, metrics):
    """Fetch statistics for each Worfklow Execution for a specific group of 
    workflow executions.

    Args:
        workflow_tags: List of workflow tags
        parameters: List of parameters
        metrics: List of metrics

    Returns:
        A JSON dictionary containing statistics per workflow execution.
    """

    workflow_tags = ','.join([f"'{x}'" for x in workflow_tags])
    parameters = ','.join([f"'{x}'" for x in parameters])
    metrics = ','.join([f"'{x}'" for x in metrics])
    
    # Compose the SQL command using the template for reading tags about a task execution
    sql = utils.sql_workflow_execution_templates['workflow_read_statistics']   

    # Execute the SQL command in the database
    resp = utils.execSql(sql, (workflow_tags, parameters, metrics, ))

    if resp and len(resp)>0:
        df = pd.DataFrame(resp)
        df = df.pivot(index='workflow_uuid', columns='key', values='value')
        df = convert_datatype(df)
        df = df.reset_index(drop=False) # avoid casting hash ids
        # print(df)
        # print(df.dtypes)
        # print(df.dtypes)
        # df = df.T
        # print(df)
        resp = df.to_dict(orient='dict')
        return resp
    else:
        return None