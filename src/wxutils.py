import hashlib
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime

import requests
from flask import current_app, jsonify

import cutils
import execution
import kutils
import sql_utils
import utils
import logging

logging.basicConfig(level=logging.DEBUG)

def is_valid_url(url):
    """Check if a string is a valid URL. Valid URLs are of the form 'protocol://hostname[:port]/path'.
    Args:
        url: The string to be checked.
    Returns:
        A boolean value indicating whether the string is a valid
    """
    pattern = re.compile(r"^(s3|https|http|tcp|smb|ftp)://[a-zA-Z0-9.-]+(?:/[^\s]*)?$")
    return bool(pattern.match(url))


def is_valid_uuid(s):
    """Check if a string is a valid UUID. Valid UUIDs are of the form 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.
    Args:
        s: The string to be checked.
    Returns:
        A boolean value indicating whether the string is a valid UUID.
    """
    try:
        # Try converting the string to a UUID object
        uuid_obj = uuid.UUID(s)
        # Check if the string matches the canonical form of the UUID (with lowercase hexadecimal and hyphens)
        return str(uuid_obj) == s
    except Exception:
        return False


def generate_task_signature(task_id):
    """Generates a signature for a given task_id by salting it with the secret key of the flask app
    and hashing it with SHA256.
    """
    secret_key = current_app.secret_key

    if not secret_key:
        raise RuntimeError("Secret key is not set in the Flask app.")

    # Salting the task_id with the secret key
    salted_task_id = task_id + secret_key
    return hashlib.sha256(salted_task_id.encode()).hexdigest()


def verify_task_signature(task_id, signature):
    """Verifies the signature of a given task_id by comparing it with the signature generated using the secret key of the flask app."""
    return signature == generate_task_signature(task_id)
    


def api_artifact_id(resource_id):
    """Get the file path of an artifact, given its resource ID.

    Provides the path to the file (URL, S3 bucket or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    config = current_app.config["settings"]

    package_headers, resource_headers = utils.create_CKAN_headers(
        config["CKAN_ADMIN_TOKEN"]
    )

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(
        config["CKAN_API"] + "resource_show?id=" + resource_id, headers=package_headers
    )  # auth=HTTPBasicAuth(config.username, config.password))

    # Get the path of this artifact
    if response.status_code == 200:
        return response.json()["result"]["url"]
    else:
        return None


def get_workflows():
    """Retrieve all workflows."""
    try:
        response = sql_utils.workflow_get_all()
        return response if response else "No workflows submitted yet."
    except Exception as e:
        raise RuntimeError(f"Workflows Could Not Be Retrieved. {e}")


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
    try:
        workflow_exec_id = str(uuid.uuid4())
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = "running"
        tags["package_id"] = package_id

        response = sql_utils.workflow_execution_create(
            workflow_exec_id, start_date, state, creator_user, package_id, tags
        )
        if not response:
            return None
        return workflow_exec_id

    except Exception as e:
        raise RuntimeError(f"Workflow could not be created. {e}")


def get_workflow_process(workflow_id):
    """Retrieve the metadata for a workflow process.

    Provides the metadata for a workflow process, including the state, start and end time, and the tags. The metadata is used to monitor the progress of a workflow process.

    Args:
        workflow_id: The unique identifier of the workflow process.
    Returns:
        A JSON with the metadata for the specified workflow process.
    """
    if not is_valid_uuid(workflow_id):
        raise AttributeError("Invalid Workflow ID provided.")

    try:
        w = sql_utils.workflow_execution_read(workflow_id)
        if w:
            return w
        else:
            raise ValueError("Workflow does not exist.")
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(f"Workflow Process Could Not Be Retrieved. {e}")


def get_workflow_tasks(workflow_id):
    """Retrieve the tasks for a workflow process.
    Args:
        workflow_id: The unique identifier of the workflow process.
    Returns:
        A JSON with the tasks for the specified workflow.
    Raises:
        AttributeError: If the workflow ID is not provided or is invalid.
        ValueError: If the workflow does not exist.
        RuntimeError: If the tasks could not be retrieved.
    """
    if not workflow_id:
        raise AttributeError("Workflow ID is required.")

    if not is_valid_uuid(workflow_id):
        raise AttributeError("Invalid Workflow ID provided.")

    if sql_utils.workflow_execution_read(workflow_id) is None:
        raise ValueError("Workflow does not exist.")

    try:
        response = sql_utils.workflow_get_tasks(workflow_id)
        return response if response else "No tasks submitted for this workflow."

    except Exception as e:
        raise RuntimeError(f"Workflow Tasks Could Not Be Retrieved. {e}")


def update_workflow_state(workflow_id, state):
    """Update the state of a workflow process. If the state is 'failed' or 'succeeded', the end date is also updated to the current time.

    Args:
        workflow_id: The unique identifier of the workflow process.
        state: The new state of the workflow process. ('running', 'failed', 'succeeded')
    Returns:
        A boolean value indicating whether the state was successfully updated.
    Raises:
    """
    if not workflow_id:
        raise AttributeError("Workflow ID is required.")

    try:
        if get_workflow_process(workflow_id) is None:
            raise ValueError("Workflow does not exist.")

        if state in ["failed", "succeeded"]:
            end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            response = sql_utils.workflow_execution_update(workflow_id, state, end_date)
            if not response:
                return False
        else:
            response = sql_utils.workflow_execution_update(
                workflow_id, state, "1970-01-01 00:00:01"
            )
            if not response:
                return False

        return True, state
    except Exception as e:
        raise RuntimeError(f"Workflow State Could Not Be Updated. {e}")


def delete_workflow_process(workflow_id):
    """Delete a workflow process.
    Args:
        workflow_id: The unique identifier of the workflow process.
    Returns:
        A boolean value indicating whether the workflow process was successfully deleted.
    Raises:
        RuntimeError: If the workflow process could not be deleted.
    """
    try:
        if not is_valid_uuid(workflow_id):
            raise AttributeError("Invalid Workflow ID provided.")

        if sql_utils.workflow_execution_read(workflow_id) is None:
            raise ValueError("Workflow does not exist.")

        response = sql_utils.workflow_execution_delete(workflow_id)
        if not response:
            return False
        return True
    except Exception as e:
        raise RuntimeError(f"Workflow Process Could Not Be Deleted. {e}")


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
        creator_user_id = userinfo.get("preferred_username", None)
    except Exception:
        raise ValueError

    try:
        tags = {}

        workflow_exec_id = json_data["workflow_exec_id"]
        input = json_data.get("inputs")
        parameters = json_data.get("parameters")
        datasets = json_data.get("datasets")
        secrets = json_data.get("secrets")
        outputs = json_data.get("outputs")

        #### CHECK WORKFLOW EXECUTION STATE AND EXISTENCE
        workflow = sql_utils.workflow_execution_read(workflow_exec_id)
        if workflow is None:
            raise RuntimeError("Workflow does not exist!")

        if workflow.get("state") != "running":
            raise AttributeError("Workflow is committed and will not accept tasks!")

        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = "running"
        task_exec_id = str(uuid.uuid4())

        response = sql_utils.task_execution_create(
            task_exec_id, workflow_exec_id, start_date, state, creator_user_id
        )
        if not response:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Workflow Execution could not be created.",
                    }
                ),
                500,
            )

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
                            resource["id"]
                            for resource in cutils.get_package_resources(
                                dataset_uuid or val, filter_value
                            )
                        ]
                        resources.extend(dataset_resources)
                    elif cutils.is_resource(dataset_uuid or val):
                        resources.append(dataset_uuid or val)
                elif is_valid_url(val):
                    resources.append(val)

            response = sql_utils.task_execution_insert_input(
                task_exec_id, resources, input_group_name
            )

            if not response:
                raise RuntimeError("Task could not be created due to a database error.")

        parameters = {k: str(v) for k, v in parameters.items()}
        response = sql_utils.task_execution_insert_parameters(task_exec_id, parameters)

        if not response:
            raise RuntimeError(
                "Task could not be created due to a database error regarding parameters."
            )
        
        if secrets:
            response = sql_utils.task_execution_insert_secrets(task_exec_id, secrets)
            if not response:
                raise RuntimeError(
                    "Task could not be created due to a database error regarding secrets."
                )


        # Future datasets are datasets that are going to be used for storing metadata when the task is completed. 
        if datasets:
            for dataset in datasets:
                value = datasets[dataset]
                # Handle the case where the value is a package_id
                if is_valid_uuid(value):
                    responses = sql_utils.task_execution_insert_future_package_existing(task_exec_id=task_exec_id, 
                                                                                        package_id=value, 
                                                                                        package_friendly_name=dataset)
                    if not responses:
                        raise RuntimeError(
                            "Task could not be created due to a database error regarding future datasets."
                        )
                # Handle the case where the value is a package_dict
                elif utils.is_valid_package_dict(value):
                    encoded_details = utils.encode_to_base64(value)
                    responses = sql_utils.task_execution_insert_future_package_details(task_exec_id=task_exec_id, 
                                                                                       package_details=encoded_details, 
                                                                                       package_friendly_name=dataset)
                    if not responses:
                        raise RuntimeError(
                            "Task could not be created due to a database error regarding future datasets."
                        )
       
        # Handle output spec to store the details of actions that need to be taken after the task is completed regarding the output files and their metadata.
        if outputs:
            for output in outputs:
                if isinstance(outputs[output], dict):
                    output_spec = outputs[output]
                    if not output_spec.get('url'):
                        raise ValueError("Output spec must contain a URL as an output for file key: " + output)
                    else:
                        url = output_spec.get('url', None)
                        if not is_valid_url(url):
                            continue

                        # Handle the metadata related fields and cases
                        if output_spec.get('resource', None):
                            # Case where there is an existing resource that we want to overwrite its data
                            resource = output_spec.get('resource')
                            if is_valid_uuid(resource):
                                response = sql_utils.task_execution_insert_output_spec_existing_resource(task_exec_id, output, 
                                                                                                         url, resource, 
                                                                                                         output_spec.get('resource_action','REPLACE'))
                                if not response:
                                    raise RuntimeError(
                                        "Task could not be created due to a database error regarding output spec at output: " + output
                                    )
                                
                            # Case where we want to create a resource in a dataset specified in the datasets above. 
                            elif isinstance(resource, dict) and output_spec.get('dataset', None):
                                dataset_friendly_name = output_spec.get('dataset')
                                if dataset_friendly_name in datasets.keys():
                                    response = sql_utils.task_execution_insert_output_spec_new_resource(task_exec_id, 
                                                                                                        output, 
                                                                                                        url, 
                                                                                                        dataset_friendly_name, 
                                                                                                        resource.get('name',''), 
                                                                                                        resource.get('label',''))
                                    if not response:
                                        raise RuntimeError(
                                            "Task could not be created due to a database error regarding output spec at output: " + output
                                        )
                                else:
                                    raise RuntimeError(f"Dataset friendly name `{dataset_friendly_name}` not found in declared datasets.")
                                    
                        # Case where we don't want any metadata to be tracked for this output file.
                        else:
                            response = sql_utils.task_execution_insert_output_spec_plain_path(task_exec_id, output, url)
                            if not response:
                                raise RuntimeError(
                                    "Task could not be created due to a database error regarding output spec at output: " + output
                                )
                            
        
        # Task can also be executed outside the cluster, in that case image was specified so we create
        # a job conditionally.

        # Check if 'docker image' or 'tool name' fields exists inside json_data
        if json_data.get("tool_name"):
            tags["tool_name"] = json_data.get("tool_name", None)

        if json_data.get("docker_image"):
            engine = execution.exec_engine()
            token = "Bearer " + token
            task_signature = generate_task_signature(task_exec_id)
            tags["container_id"], tags["job_id"] = engine.create_task(
                json_data.get("docker_image"), 
                token, 
                task_exec_id,
                task_signature
            )
            tags["tool_image"] = json_data.get("docker_image")

        response = sql_utils.task_execution_update(task_exec_id, state, tags=tags)
        if not response:
            raise RuntimeError(
                "Task could not be created due to an execution engine error."
            )

        return {
            "task_exec_id": task_exec_id,
            "job_id": tags.get("job_id", "Remote Task Mode"),
            "signature": generate_task_signature(task_exec_id),
        }
    except Exception as e:
        raise RuntimeError(f"Task could not be created. {e}")


def get_task_metadata(task_id):
    """Retrieve the metadata for a task execution.

    Provides the metadata for a task execution, including the state,
    start and end time, and the tags. The metadata is used to monitor
    the progress of a task execution.

    Args:
           task_id: The unique identifier of the task execution.
    Returns:
           A JSON with the metadata for the specified task id.
    """

    try:
        d = dict()

        t = sql_utils.task_execution_read(task_id)
        if t:
            d.update(sql_utils.task_execution_read(task_id))

            if d["tags"].get("tool_image"):
                d["tool_image"] = d["tags"]["tool_image"]

            if d["tags"].get("tool_name"):
                d["tool_name"] = d["tags"]["tool_name"]

            state = d["state"]

            if state != "failed" and state != "succeeded":
                return d

            d["messages"] = d["tags"]["log"]

            d["output"] = sql_utils.task_execution_output_read(task_id)
            d["metrics"] = sql_utils.task_execution_metrics_read(task_id)

            return d
        else:
            raise ValueError("Task does not exist.")
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(f"Task Metadata Could Not Be Retrieved. {e}")


def get_task_logs(task_id):
    """Retrieve the logs for a task execution.

    Provides the logs for a task execution. The logs are used to monitor the progress of a
    task execution and to debug issues.

    Args:
           task_id: The unique identifier of the task execution.
    Returns:
           A JSON with the logs for the specified task
    """
    engine = execution.exec_engine()
    logs = engine.fetch_task_logs(task_id)
    return logs


def get_task_info(task_id):
    """Retrieve the info for a task execution.

    Provides the state, logs for a task execution. The logs are used to monitor the progress
    of a task execution and to debug issues.

    Args:
           task_id: The unique identifier of the task execution.
    Returns:
           A JSON with the logs for the specified task
    """
    engine = execution.exec_engine()
    logs = engine.get_task_info(task_id)
    return logs


def delete_task(task_id):
    """Delete a task execution.

    Deletes a task execution based on the input task id provided. The task execution is removed from the database
    and the deletion cascades to the associated input groups, parameters, and outputs (specs).

    Args:
           task_id: The unique identifier of the task execution.
    Returns:
           A boolean value indicating whether the task execution was successfully deleted.
    """
    try:
        # Check if the task exists. Throws an exception if it does not.
        get_task_metadata(task_id)
        response = sql_utils.task_execution_delete(task_id)
        return bool(response)

    except ValueError:
        raise
    except Exception:
        return False


def get_task_input_json(task_id, signature=None, access_token=None):
    """Retrieve the input JSON for a task execution. This is the JSON the tool finally receives.

    Provides the input JSON for a task execution, including the input groups and the parameters.
    The input JSON is used to create a task execution.

    Args:
           task_id: The unique identifier of the task execution.
           access_token: The access token for MinIO. (Default is None)
    Returns:
           A JSON with the input groups, parameters and MinIO credentials (if access_token was
           provided and was valid) for the specified task id.
    """
    if is_valid_uuid(task_id):
        task_exec_id = task_id
        config = current_app.config["settings"]

        # Check if the task exists
        try:
            get_task_metadata(task_exec_id)
        except ValueError:
            raise ValueError("Task does not exist.")

        # Fetch the input groups and the parameters for the task execution from the database
        input = sql_utils.task_execution_input_read_sql(task_exec_id)
        parameters = sql_utils.task_execution_parameters_read(task_exec_id)

        access_key = secret_key = session_token = None

        if access_token:
            # Produce STS Token for MinIO Access
            minio_body = {
                "Action": "AssumeRoleWithWebIdentity",
                "WebIdentityToken": access_token,
                "Version": "2011-06-15",
                "DurationSeconds": "86000",
            }
            minio_url = config["MINIO_API_EXT_URL"]

            # Make a POST request to MinIO's STS endpoint to retrieve credentials, if any.
            try:
                response = requests.post(url=minio_url, params=minio_body, verify=False)
            except requests.exceptions.RequestException:
                pass

            # Handle the response, parse XML if successful
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    # Extracting relevant information from the XML
                    credentials = root.find(
                        ".//{https://sts.amazonaws.com/doc/2011-06-15/}Credentials"
                    )
                    if credentials is not None:
                        access_key = (
                            credentials.find(
                                "{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId"
                            ).text
                            if credentials.find(
                                "{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId"
                            )
                            is not None
                            else None
                        )
                        secret_key = (
                            credentials.find(
                                "{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey"
                            ).text
                            if credentials.find(
                                "{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey"
                            )
                            is not None
                            else None
                        )
                        session_token = (
                            credentials.find(
                                "{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken"
                            ).text
                            if credentials.find(
                                "{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken"
                            )
                            is not None
                            else None
                        )
                except ET.ParseError as e:
                    pass

        try:
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
                }
            else:
                result = {
                    'input': input_paths, 
                    'parameters': parameters,  
                    'minio':{
                        'endpoint_url': config["MINIO_API_EXT_URL"]
                    }
                }
            
            # Read the paths for the output files that the tool will write to.
            output = sql_utils.task_read_output_spec(task_exec_id)
            if output:
                result["output"] = output

            # If the request is signed, we verify the signature to include secret information.
            if signature:
                if verify_task_signature(task_exec_id, signature):
                    # Fetch the secrets for the task execution from the database
                    secrets = sql_utils.task_execution_read_secrets(task_exec_id)
                    if secrets:
                        secrets_dict = {}
                        # Iterate over the list of secrets and add key-value pairs to the new dictionary
                        secrets_dict = {secret["key"]: secret["value"] for secret in secrets}
                        result.update({"secrets": secrets_dict})
                    result["signature_verified"] = True

            return result

        except Exception as e:
            raise RuntimeError(f"Task Input Could Not Be Retrieved. {e}")
    else:
        raise AttributeError("Invalid Task ID provided.")


def get_task_output_json(task_id, signature, output_json):
    """
    Update the task execution with the output JSON provided. The output JSON includes the state, metrics, messages, and the output files.
    Args:
        task_id: The unique identifier of the task execution.
        signature: The signature of the task execution.
        output_json: The output JSON for the task execution.
    Returns:
        A boolean value indicating whether the output JSON was successfully updated.
    Raises:
        AssertionError: If the task signature is invalid.
        AttributeError: If the task ID is invalid.
        ValueError: If the task does not exist.
    """

    if verify_task_signature(task_id, signature) is False:
        raise AssertionError("Invalid Task Signature.")
        
    if not is_valid_uuid(task_id):
        raise AttributeError("Invalid Task ID provided.")
    
    if sql_utils.task_execution_read(task_id) is None:
        raise ValueError("Task does not exist.")    

    outputs = output_json["output"]
    for output in outputs:
        output_url = outputs[output]
        output_spec = sql_utils.task_read_output_spec_of_file(task_id, output)
        
        if output_spec:
            if output_url == output_spec.get("output_address",""):

                # Handle the case where an existing resource should be updated with the new output path of the tool output.
                if output_spec.get("resource_id"):
                    updated_metadata = {}
                    if output_spec.get("resource_name"):
                        updated_metadata["name"] = output_spec.get("resource_name")
                    if output_spec.get("resource_label"):
                        updated_metadata["relation"] = output_spec.get("resource_label")
                    updated_metadata["url"] = output_url
                    try:
                        result = cutils.patch_resource(output_spec.get("resource_id"), updated_metadata)
                    except Exception:
                        pass
                
                # Handle the case where a refenence to a dataset is included in the spec and we need to create a new resource in that dataset.
                # or also create the dataset itself.
                
                if output_spec.get("dataset_friendly_name"):
                    # Package does not exist should be created
                    if output_spec.get("package_details"):
                        try:
                            decoded_package = utils.decode_from_base64(output_spec.get("package_details"))
                            decoded_package["tags"].append("Workflow")
                            cutils.create_package(basic_metadata=decoded_package)
                        except Exception:
                            continue
                    # Package exists, we should create a resource inside it
                    elif output_spec.get("package_id"):
                        try:
                            resource_metadata = {}
                            resource_metadata["name"] = output_spec.get("resource_name")
                            resource_metadata["url"] = output_url
                            cutils.create_resource(output_spec.get("package_id"), resource_metadata, output_spec.get("resource_label"))
                        except Exception:
                            continue

                        


    # Now handle the metrics, messages and state of the task.
    state = output_json.get("state")
    messages = output_json.get("messages")
    metrics = output_json.get("metrics")


    if metrics:
        sql_utils.task_execution_insert_metrics(task_id, metrics)
    
    if messages:
        sql_utils.task_execution_insert_log(task_id, messages)
    
    if state:
        sql_utils.task_execution_update(task_id, state, end_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    return True