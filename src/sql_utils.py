import ast
import json
import logging
import re
import uuid
from datetime import datetime

import pandas as pd
import requests
from flask import current_app

import utils
from backend import pgsql

# Auxiliary custom functions & SQL query templates for ranking
from exceptions import BackendLogicError


def is_valid_uuid(s):
    try:
        # Try converting the string to a UUID object
        uuid_obj = uuid.UUID(s)
        # Check if the string matches the canonical form of the UUID (with lowercase hexadecimal and hyphens)
        return str(uuid_obj) == s
    except ValueError:
        return False


def is_valid_url(url):
    pattern = re.compile(r"^(s3|https|http|tcp|smb|ftp)://[a-zA-Z0-9.-]+(?:/[^\s]*)?$")
    return bool(pattern.match(url))


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


"""
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
"""


##########################################################
## Policy Management
##########################################################
def policy_version_create(
    policy_uuid, policy_familiar_name, active, yaml_content, user_id
) -> str:
    """Records in the database that the user-specified parameters for the given policy

    Args:
        policy_uuid: UUID of the policy_version
        parameters: A JSON dictionary with parametrization as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution
    sql = utils.sql_policy_template["policy_create_template"]
    resp = pgsql.execSql(
        sql, (policy_uuid, policy_familiar_name, active, yaml_content, user_id)
    )
    if "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def list_policies():
    sql = utils.sql_policy_template["policy_get_all_info_template"]
    resp = pgsql.execSql(sql)
    if resp and len(resp) > 0:
        policies = resp
        return policies
    else:
        return None


def policy_representation_read(filter):
    if is_valid_uuid(filter):
        sql = utils.sql_policy_template["policy_get_yaml_by_id_template"]
        resp = pgsql.execSql(sql, (filter,))
        if resp and len(resp) > 0:
            policy_version = resp[0]
            return policy_version["yaml_content"]
        else:
            return None
    elif filter == "active":
        sql = utils.sql_policy_template["policy_get_yaml_by_state_template"]
        resp = pgsql.execSql(sql, (True,))
        if resp and len(resp) > 0:
            policy_version = resp[0]

            return policy_version["yaml_content"]
        else:
            return None


def policy_info_read(filter):
    if is_valid_uuid(filter):
        sql = utils.sql_policy_template["policy_get_info_by_id_template"]
        resp = pgsql.execSql(sql, (filter,))
        if resp and len(resp) > 0:
            policy_version = resp[0]
            return policy_version
        else:
            return None
    elif filter == "active":
        sql = utils.sql_policy_template["policy_get_info_by_state_template"]
        resp = pgsql.execSql(sql, (True,))
        if resp and len(resp) > 0:
            policy_version = resp[0]
            return policy_version
        else:
            return None


##########################################################
## 2FA Management
##########################################################
def two_factor_auth_create(user_id, secret) -> str:
    """
    Creates a two-factor authentication entry for a user.

    Args:
        user_id (str): The unique identifier of the user.
        secret (str): The secret key for two-factor authentication.

    Returns:
        str: Returns a status string indicating the result of the operation.
             Returns False if the operation fails.
    """
    if user_id and secret:
        sql = utils.sql_2fa_template["two_factor_create_template"]
        resp = pgsql.execSql(sql, (user_id, secret))
        if resp and "status" in resp:
            if not resp.get("status"):
                return False
            else:
                return True
        else:
            return False


def two_factor_revoke(user_id) -> str:
    """
    Revokes two-factor authentication for a given user.

    Args:
        user_id (int): The ID of the user for whom two-factor authentication should be revoked.

    Returns:
        bool: Returns 'False' if the revocation was unsuccessful, otherwise returns the response status.
    """
    if user_id:
        sql = utils.sql_2fa_template["two_factor_revoke_template"]
        resp = pgsql.execSql(sql, (user_id,))
        if "status" in resp:
            if not resp.get("status"):
                return False
            else:
                return True

    return False


def two_factor_auth_retrieve(user_id) -> str:
    """
    Retrieve the two-factor authentication secret key for a given user.

    Args:
        user_id (str): The unique identifier of the user.

    Returns:
        str: The two-factor authentication secret key associated with the user.

    Note:
        This function queries the database using a predefined SQL template to
        retrieve the secret key for the specified user. If the user exists and
        has a secret key, it returns the key; otherwise, it returns None.
    """
    if user_id:
        sql = utils.sql_2fa_template["two_factor_retrieve_skey_template"]
        resp = pgsql.execSql(sql, (user_id,))
        if resp and len(resp) > 0:
            secret = resp[0]
            return secret


def two_factor_user_has_2fa(user_id) -> str:
    """Check if a user has two-factor authentication enabled.

    Args:
        user_id: The unique identifier of the user.

    Returns:
        A boolean: True if the user has two-factor authentication enabled, otherwise False.
    """

    if user_id:
        sql = utils.sql_2fa_template["two_factor_check_template"]
        resp = pgsql.execSql(sql, (user_id,))
        if resp and len(resp) > 0:
            return True
        else:
            return False


def stat_two_factor_for_user(user_id) -> str:
    """Check if a user has two-factor authentication enabled.

    Args:
        user_id: The unique identifier of the user.

    Returns:
        A boolean: True if the user has two-factor authentication enabled, otherwise False.
    """

    if user_id:
        sql = utils.sql_2fa_template["two_factor_check_template"]
        resp = pgsql.execSql(sql, (user_id,))
        if resp and len(resp) > 0:
            secret = resp[0]
            return secret
        else:
            return None


##########################################################
## Workflow Execution Metadata Management
##########################################################
def workflow_execution_create(
    workflow_exec_id: uuid.UUID | str,
    start_date: datetime,
    state,
    creator_user_id: str,
    wf_package_id: uuid.UUID | str | None = None,
    tags=None,
):
    """Records metadata for a new workflow execution in the database.

    Args:
        workflow_exec_id: UUID of the new workflow execution.
        start_date: Start timestamp of the new workflow execution.
        state: Initial state of the new workflow execution.
        creator_user_id: The unique username of the user creating the workflow.
        wf_package_id: Optionally the package which will be used as context for the workflow.
        tags: A JSON dictionary with workflow execution metadata as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    with pgsql.transaction() as conn:
        # Compose the SQL command using the template for creating a new workflow execution
        sql = utils.sql_workflow_execution_templates["workflow_create_template"]
        resp = pgsql.execSql(
            sql,
            (workflow_exec_id, state, creator_user_id, start_date, wf_package_id),
        )
        if not resp["status"]:
            raise BackendLogicError(
                "Failed to insert new workflow execution record in the database",
                workflow_exec_id,
            )

        # Add any tags
        if tags:
            sql = utils.sql_workflow_execution_templates[
                "workflow_insert_tags_template"
            ]

            for key, value in tags.items():
                # Execute the SQL command in the database
                resp = pgsql.execSql(sql, (workflow_exec_id, key, value))
                if not resp["status"]:
                    raise BackendLogicError(
                        "Failed to insert new workflow execution record in the database",
                        workflow_exec_id,
                    )


def workflow_execution_update(workflow_exec_id, state, end_date=None):
    """Updates metadata regarding a workflow execution in the database.

    Args:
        workflow_exec_id: UUID of a workflow execution.
        state: Current state of this workflow execution.
        end_date: Timestamp marking the end of this workflow execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose and execute the SQL command using the template for updating/commiting a workflow execution
    if end_date is not None:
        sql = utils.sql_workflow_execution_templates["workflow_commit_template"]
        resp = pgsql.execSql(sql, (state, end_date, workflow_exec_id))
    else:
        sql = utils.sql_workflow_execution_templates["workflow_update_template"]
        resp = pgsql.execSql(sql, (state, workflow_exec_id))

    return resp.get("status", False)


def workflow_execution_update_wf_package(workflow_exec_id, package_id):
    """Updates metadata regarding a workflow execution in the database.

    Args:
        workflow_exec_id: UUID of a workflow execution.
        package_id: The ID of the package that will be used as context for the workflow.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose and execute the SQL command using the template for updating/commiting a workflow execution
    sql = utils.sql_workflow_execution_templates["workflow_update_wf_package"]
    resp = pgsql.execSql(sql, (package_id, workflow_exec_id))
    return resp.get("status", False)


def workflow_execution_delete(workflow_exec_id):
    """Deletes all metadata regarding a workflow execution from the database. CAUTION! This also includes all metadata about task executions associated with this workflow execution.

    Args:
        workflow_exec_id: UUID of a workflow execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for deleting a workflow execution
    sql = utils.sql_workflow_execution_templates["workflow_delete_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (workflow_exec_id,))

    return resp.get("status", False)


def workflow_execution_read(workflow_exec_id):
    """Returns metadata recorded in the database about the given workflow execution. User-specified tags are included in the returned response.

    Args:
        workflow_exec_id: UUID of the workflow execution.

    Returns:
        A JSON with the workflow execution metadata, including the tags.
    """

    # Compose the SQL command using the template for reading metadata about a workflow execution
    sql = utils.sql_workflow_execution_templates["workflow_read_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (workflow_exec_id,))

    if resp and len(resp) > 0:
        # List should contain specification of a single workflow execution (unique UUID)
        workflow_specs = resp[0]
        # Also include any user-specified tags in the response
        workflow_specs["tags"] = workflow_execution_tags_read(workflow_exec_id)
        return workflow_specs
    else:
        return None


def workflow_execution_context_read(workflow_exec_id):
    """Returns the ID of the contextual package corresponding to the working during its creation.
       If not specified returns null

    Args:
        workflow_exec_id: UUID of the workflow execution.

    Returns:
        A JSON with the ID of the package if specified.
    """

    # Compose the SQL command using the template for reading metadata about a workflow execution
    sql = utils.sql_workflow_execution_templates["workflow_get_context_package"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (workflow_exec_id,))

    if resp and len(resp) > 0:
        workflow_context = resp[0]
        return workflow_context
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
    sql = utils.sql_workflow_execution_templates["workflow_read_tags_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (workflow_exec_id,))

    if resp and len(resp) > 0:
        tag_dict = {tag["key"]: tag["value"] for tag in resp}
        return tag_dict
    else:
        return None


def task_execution_create(
    task_exec_id,
    workflow_exec_id,
    start_date,
    state,
    creator_user_id,
    tags=None,
    prev_task_exec_id=None,
):
    """Records metadata for a new task execution in the database.

    Args:
        workflow_exec_id: UUID of an existing workflow execution.
        task_exec_id: UUID of the new task execution.
        start_date: Start timestamp of the new task execution.
        state: Initial state of the new task execution.
        creator_user_id: The unique username of the user creating the task.
        tags: A JSON dictionary with task execution metadata as (key, value) pairs.
        prev_task_exec_id: UUID of the exexcution of the previous task in the workflow pipeline.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for creating a new task execution
    sql = utils.sql_workflow_execution_templates["task_create_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(
        sql, (task_exec_id, workflow_exec_id, creator_user_id, state, start_date)
    )
    if resp and "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    # Compose the SQL command using the template for specifying the previously executed task
    if prev_task_exec_id:
        sql = utils.sql_workflow_execution_templates["task_create_connection_template"]

        # Execute the SQL command in the database
        resp = pgsql.execSql(sql, (task_exec_id, prev_task_exec_id))
        if resp and "status" in resp:
            if not resp.get("status"):
                return False
        else:
            return False

    # Compose the SQL command using the template for assigning tags to the new task execution
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates["task_insert_tags_template"]

            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, key, value))
            if resp and "status" in resp:
                if not resp.get("status"):
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
        sql = utils.sql_workflow_execution_templates["task_commit_template"]
        resp = pgsql.execSql(sql, (state, end_date, task_exec_id))
    else:
        sql = utils.sql_workflow_execution_templates["task_update_template"]
        resp = pgsql.execSql(sql, (state, task_exec_id))

    if resp and "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    # Compose the SQL command using the template for assigning tags to the new task execution
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates["task_insert_tags_template"]

            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, key, value))
            if resp and "status" in resp:
                if not resp.get("status"):
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
    sql = utils.sql_workflow_execution_templates["task_delete_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id,))

    if resp and "status" in resp:
        if not resp.get("status"):
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
    sql = utils.sql_workflow_execution_templates["task_insert_tags_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id, "log", log))
    if resp and "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def resource_get_url_by_id(resource_id):
    """Returns the path of a resource given its ID.

    Args:
        resource_id: UUID of the resource.

    Returns:
        A string with the path of the resource.
    """

    # Compose the SQL command using the template for reading metadata about a task execution
    sql = utils.sql_workflow_execution_templates["resource_read_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (resource_id,))

    if resp and len(resp) > 0:
        return resp[0]["url"]
    else:
        return None


def task_execution_insert_input(task_exec_id, inputs, input_group_name):
    """Records in the database that the given dataset id was used as input in the given task execution.
    The input will be inserted with the order the were provided in the inputs array.

    Args:
        task_exec_id: UUID of the task execution.
        inputs: Array of UUIDs mixed in with Paths to be used as input in this task execution.
        input_group_name: The key of the JSON field mapping to the array/list of inputs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording input datasets
    for idx, inp in enumerate(inputs):
        # In case we get a UUID as input we pass it as is
        if is_valid_uuid(inp):
            sql = utils.sql_workflow_execution_templates[
                "task_insert_input_by_uuid_template"
            ]
            # Find the url corresponding to the resource UUID in the database
            url = resource_get_url_by_id(inp)

            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, idx, inp, url, input_group_name))
            if resp and "status" in resp:
                if not resp.get("status"):
                    return False
            else:
                return False

        # In case we get a Path as input we pass it as is if it acceptable
        elif is_valid_url(inp):
            sql = utils.sql_workflow_execution_templates[
                "task_insert_input_by_path_template"
            ]
            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, idx, inp, input_group_name))
            if resp and "status" in resp:
                if not resp.get("status"):
                    return False
            else:
                return False

    return True


def task_execution_insert_output(task_exec_id, resources):
    """Records in the database that the given dataset id was issued as output from the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        resources: Array of dict of the resource(s) (i.e.,CKAN resources) issued as output from this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording output datasets
    for idx, res in enumerate(resources):
        sql = utils.sql_workflow_execution_templates[
            "task_insert_output_dataset_template"
        ]

        # Execute the SQL command in the database
        resp = pgsql.execSql(
            sql, (task_exec_id, idx, res["resource_id"], res["output"])
        )
        if resp and "status" in resp:
            if not resp.get("status"):
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
            sql = utils.sql_workflow_execution_templates[
                "task_insert_parameters_template"
            ]

            # Convert the value to a valid JSON string
            json_value = json.dumps(value)

            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, key, json_value))
            if "status" in resp:
                if not resp.get("status"):
                    return False
            else:
                return False

    return True


def task_execution_insert_secrets(task_exec_id, secrets):
    """Records in the database that the user-specified secrets for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        secrets: A JSON dictionary with the task execution secrets as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution
    if secrets:
        for key, value in secrets.items():
            sql = utils.sql_workflow_execution_templates["task_insert_secret_template"]

            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, key, value))
            if "status" in resp:
                if not resp.get("status"):
                    return False
            else:
                return False

    return True


def task_execution_read_secrets(task_exec_id):
    """
        Submit a request to the Metadata Database to retrieve information about the secrets
        of a task execution with given id

    Returns:
        A JSON with the secrets, if any.
    """

    sql = utils.sql_workflow_execution_templates["task_read_secret_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id,))

    if resp and len(resp) > 0:
        task_secs = resp
        return task_secs
    else:
        return None


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
            sql = utils.sql_workflow_execution_templates["task_insert_metrics_template"]

            # Execute the SQL command in the database
            resp = pgsql.execSql(sql, (task_exec_id, key, value))
            if "status" in resp:
                if not resp.get("status"):
                    return False
            else:
                return False

    return True


def task_execution_insert_future_package_existing(
    task_exec_id, package_id, package_friendly_name
):
    """Records in the database that the future user-specified package_id for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        package_id: The package_id of the package that will be used as context for the task execution.
        package_friendly_name: The friendly name for the package as specified in the tool spec json.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution
    sql = utils.sql_workflow_execution_templates["task_insert_existing_future_package"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id, package_id, package_friendly_name))
    if "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def task_execution_insert_future_package_details(
    task_exec_id, package_details, package_friendly_name
):
    """Records in the database that the future user-specified package_id for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        package_details: The string describing the details of the package that will be used as context for the task execution encoded in base64.
        package_friendly_name: The friendly name for the package as specified in the tool spec json.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution
    sql = utils.sql_workflow_execution_templates["task_insert_future_package_details"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id, package_details, package_friendly_name))
    if "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def task_execution_insert_output_spec_new_resource(
    task_exec_id,
    output_name,
    output_address,
    dataset_friendly_name,
    resource_name,
    resource_label,
):
    sql = utils.sql_workflow_execution_templates["task_insert_output_spec_new_resource"]
    # Execute the SQL command in the database
    resp = pgsql.execSql(
        sql,
        (
            task_exec_id,
            output_name,
            output_address,
            dataset_friendly_name,
            resource_name,
            resource_label,
        ),
    )
    if "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def task_execution_insert_output_spec_existing_resource(
    task_exec_id, output_name, output_address, resource_id, resource_action
):
    sql = utils.sql_workflow_execution_templates[
        "task_insert_output_spec_existing_resource"
    ]
    # Execute the SQL command in the database
    resp = pgsql.execSql(
        sql, (task_exec_id, output_name, output_address, resource_id, resource_action)
    )
    if "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def task_execution_insert_output_spec_plain_path(
    task_exec_id, output_name, output_address
):
    sql = utils.sql_workflow_execution_templates["task_insert_output_spec_plain_path"]
    resp = pgsql.execSql(sql, (task_exec_id, output_name, output_address))
    if "status" in resp:
        if not resp.get("status"):
            return False
    else:
        return False

    return True


def task_read_output_spec(task_exec_id):
    # Compose the SQL command using the template for reading metadata about a task execution
    sql = utils.sql_workflow_execution_templates["task_read_output_spec_for_tool"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id,))

    if resp and len(resp) > 0:
        output_spec = {}
        output_spec = {
            output["output_name"]: output["output_address"] for output in resp
        }
        return output_spec
    else:
        return None


def task_read_output_spec_of_file(task_exec_id, file_key):
    """
    Retrieves the full specification regarding the handling of a tool output file. Both metadata
    and data handling.
    """
    sql = utils.sql_workflow_execution_templates["task_read_output_spec_of_file"]

    resp = pgsql.execSql(sql, (task_exec_id, file_key))

    if resp and len(resp) > 0:
        output_spec = resp[0]
        return output_spec
    else:
        return None


def task_read_dataset(task_id, dataset_friendly_name):
    sql = utils.sql_workflow_execution_templates["task_read_dataset_by_uuid_template"]

    resp = pgsql.execSql(sql, (task_id, dataset_friendly_name))

    if resp and len(resp) > 0:
        dataset = resp[0]
        return dataset
    else:
        return None


def task_execution_read(task_exec_id):
    """Returns metadata recorded in the database about the given task execution. User-specified tags are included in the returned response.

    Args:
        task_exec_id: UUID of the task execution.

    Returns:
        A JSON with the task execution metadata.
    """

    # Compose the SQL command using the template for reading metadata about a task execution
    sql = utils.sql_workflow_execution_templates["task_read_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id,))

    if resp and len(resp) > 0:
        task_specs = resp[
            0
        ]  # List should contain specification of a single task execution (unique UUID)
        # Also include any user-specified tags in the response
        task_specs["tags"] = task_execution_tags_read(task_exec_id)
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
    sql = utils.sql_workflow_execution_templates["task_read_tags_template"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql, (task_exec_id,))

    if resp and len(resp) > 0:
        tag_dict = {tag["key"]: tag["value"] for tag in resp}
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

    config = current_app.config["settings"]
    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_input_template", task_exec_id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    j = json.loads(response.text)
    print(j)
    res_ids = [res["resource_id"]["value"] for res in j["results"]["bindings"]]

    # # Compose the SQL command using the template for reading tags about a task execution
    # sql = utils.sql_workflow_execution_templates['task_read_input_dataset_template']

    # # Execute the SQL command in the database
    # resp = pgsql.execSql(sql, (task_exec_id, ))
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

    config = current_app.config["settings"]

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_output_template", task_exec_id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    j = json.loads(response.text)
    res_ids = [res["resource_id"]["value"] for res in j["results"]["bindings"]]

    # # Compose the SQL command using the template for reading tags about a task execution
    # sql = utils.sql_workflow_execution_templates['task_read_output_dataset_template']

    # # Execute the SQL command in the database
    # resp = pgsql.execSql(sql, (task_exec_id, ))
    # if resp and len(resp)>0:
    #     res_ids = [res['dataset_id'] for res in resp]
    #     return res_ids
    # else:
    #     return None

    return res_ids


def task_execution_input_read_sql(task_exec_id):
    """Submit a request to the DB to retrieve the inputs specified for the task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the input resourced ids or path grouped by input group name.
    """
    sql_groups = utils.sql_workflow_execution_templates[
        "task_read_input_group_names_by"
    ]
    resp = pgsql.execSql(sql_groups, (task_exec_id,))

    inputs = dict()

    if resp and len(resp) > 0:
        for group in resp:
            list_of_inputs = list()
            sql_inputs = utils.sql_workflow_execution_templates[
                "task_read_inputs_by_group_name"
            ]
            resp = pgsql.execSql(
                sql_inputs,
                (
                    task_exec_id,
                    group["input_group_name"],
                ),
            )
            if resp and len(resp) > 0:
                for input in resp:
                    list_of_inputs.append(input["resource_id"] or input["input_path"])
                inputs[group["input_group_name"]] = list_of_inputs

    return inputs


def task_execution_parameters_read(task_exec_id):
    """Submit a request to the Knowledge Graph retrieve the parameters specified for the task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the parameters specified in MLFlow for the specified task execution.
    """

    config = current_app.config["settings"]

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter(
        "task_execution_parameters_template", task_exec_id
    )
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    # return json.loads(response.text)
    j = json.loads(response.text)
    parameters = {
        res["parameter"]["value"]: res["value"]["value"]
        for res in j["results"]["bindings"]
    }
    parameters = cast_dict(parameters)
    return parameters


def task_execution_parameters_read_sql(task_exec_id):
    if task_exec_id:
        sql = utils.sql_workflow_execution_templates["task_read_parameters_template"]

        # Execute the SQL command in the database
        resp = pgsql.execSql(sql, (task_exec_id,))

        if resp and len(resp) > 0:
            params = {}
            for param in resp:
                value = param["value"]
                try:
                    value = int(value)
                except (ValueError, TypeError, Exception):
                    pass
                params[param["key"]] = value
            return params
        else:
            return None


def task_execution_metrics_read_sql(task_exec_id):
    if task_exec_id:
        sql = utils.sql_workflow_execution_templates["task_read_metrics_template"]

        # Execute the SQL command in the database
        resp = pgsql.execSql(sql, (task_exec_id,))

        if resp and len(resp) > 0:
            metrics = {tag["key"]: tag["value"] for tag in resp}
            return metrics
        else:
            return None


def task_execution_read_outputs_sql(task_exec_id):
    if task_exec_id:
        sql = utils.sql_workflow_execution_templates[
            "task_read_output_with_paths_template"
        ]

        # Execute the SQL command in the database
        resp = pgsql.execSql(sql, (task_exec_id,))

        if resp and len(resp) > 0:
            return resp
        else:
            return None


def task_execution_metrics_read(task_exec_id):
    """Submit a request to the Knowledge Graph retrieve the metrics issued for the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the metrics collected in MLFlow for the specified task execution.
    """

    config = current_app.config["settings"]

    sparql_headers = {
        "Content-Type": "application/sparql-query",
        "Accept": "application/json",
    }
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter("task_execution_metrics_template", task_exec_id)
    #    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(
        config["SPARQL_ENDPOINT"], headers=sparql_headers, data=sparql
    )

    # return jsonify(json.loads(response.text))
    j = json.loads(response.text)
    metrics = {
        res["metric"]["value"]: res["value"]["value"]
        for res in j["results"]["bindings"]
    }
    metrics = cast_dict(metrics)

    return metrics


def workflow_get_tasks(workflow_exec_id):
    """Submit a request to the Metadata Database to retrieve information about all tasks
        belonging to a workflow execution with given id

    Args:
        id: The identifier (UUID) assigned to a worfklow execution

    Returns:
        A JSON array with the tasks, if any, belonging to the workflow
    """

    if workflow_exec_id:
        sql = utils.sql_workflow_execution_templates["workflow_get_tasks"]

        # Execute the SQL command in the database
        return pgsql.execSql(sql, (workflow_exec_id,))


def workflow_get_all():
    """
        Submit a request to the Metadata Database to retrieve information about all workflow
        executions. If an execution contains a reference to the package_id, it will be available
        in the result.

    Returns:
        A JSON with the workflows, if any.
    """

    sql = utils.sql_workflow_execution_templates["workflow_get_all"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(sql)

    if resp and len(resp) > 0:
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

    workflow_tags = ",".join([f"'{x}'" for x in workflow_tags])
    parameters = ",".join([f"'{x}'" for x in parameters])
    metrics = ",".join([f"'{x}'" for x in metrics])

    # Compose the SQL command using the template for reading tags about a task execution
    sql = utils.sql_workflow_execution_templates["workflow_read_statistics"]

    # Execute the SQL command in the database
    resp = pgsql.execSql(
        sql,
        (
            workflow_tags,
            parameters,
            metrics,
        ),
    )

    if resp and len(resp) > 0:
        df = pd.DataFrame(resp)
        df = df.pivot(index="workflow_uuid", columns="key", values="value")
        df = convert_datatype(df)
        df = df.reset_index(drop=False)  # avoid casting hash ids
        # print(df)
        # print(df.dtypes)
        # print(df.dtypes)
        # df = df.T
        # print(df)
        resp = df.to_dict(orient="dict")
        return resp
    else:
        return None
