import hashlib
import logging
import re
import uuid
from datetime import datetime
from typing import Optional

from apiflask import Schema, fields, validators
from flask import current_app
from mutils import get_temp_minio_credentials, expand_wildcard_path
from processes import PROCESS
import cutils
import execution
import kutils
import sql_utils
import utils
from backend.pgsql import transaction
from entity import Entity
from exceptions import (
    ConflictError,
    DataError,
    NotAllowedError,
    NotFoundError,
    AuthorizationError,
)
from utils import is_valid_url, is_valid_uuid

logger = logging.getLogger(__name__)


"""
    Tasks:
    ===================
    Tasks are discrete units of tool logic execution that operate a set of computations.
    They are either executed as Kubernetes Jobs within the KLMS cluster or
    deployed in a remote environment, depending on the specific execution requirements.
    While the concept of a Task can be interpreted as a generic execution, we mainly 
    use tasks as vessels for the execution of the STELAR Tools on data present in the storage
    layer, indexed by the data catalog packages.
    
    Task executions are mainly recorded in the database, while their presence
    in the data catalog, enfolded within 'Process' packages, is still under discussion.

    A 'Process' serves as a parent entity for a collection of tasks, structuring them into
    a sequential chain of execution steps, where each corresponds to a distinct task.
    All tasks within the same Process are designed to execute a coordinated sequence
    of computations, ensuring a structured and systematic workflow execution.

    --------- Process --------
    |  -----    -----        |
    |  | T | -> | T | -> ... |
    |  -----    -----        |
    --------------------------

    Each Task is identified by a UUID, by which it is universally known to the entire
    ecosystem of components.

    Database is responsible for storing the following generic fields:
    - uuid: The unique identifier of the Task in UUID format.
    - process_uuid: The unique identifier of the 'Process' the task belongs to.
    - creator: The username (unique) of the user who created the process.
    - state: The state of the process. Can be 'running', 'failed', 'succeeded'.
    - start_date: The date and time when the process was started.
    - end_date: The date and time when the process was completed.

    Of the above, all are read-only except 'exec_state' which can be updated by the user,
    (albeit, only once, from 'running' to either 'failed' or 'succeeded').

    A Task requires a plan upon which the executor will adhere on to perform it.
    The specifications required vary per task and tool type. We set the below attributes
    as the minimum required definitions for the creation of a task. Attributes outlined
    below may be referring to other entities present in the data catalog of STELAR.
    - parameters: Tool specific parameters in a dict format { k:str -> v:object }
    - datasets: The datasets used either as inputs or as destination for outputs. Can be UUIDs
                of existing packages or specs for creating new ones. Each can be referenced by 
                its assigned friendly name.
    - inputs: The inputs of the execution. Can be UUIDs corresponding to datasets, resources or
              plain paths. Dataset UUIDs are translated to all 'owned' resources of the dataset
              (if no filter provided) while Resource UUIDs are translated into the path pointed by it.
              Dataset UUIDs can be also accompanied by a filter in the form UUID::filter
              which is applied with respect to the relation of the resources to the parent dataset (UUID).
              A special 'ctx' package identifier can be used as a reference to a package and is translated
              to the 'Process' package UUID the Task belongs to. 'ctx' can be used as any classic
              dataset UUID (ctx or ctx::filter).
              Note that inputs are organized in nested arrays of strings in the form of a dict:
              inputs : { k:str -> v:list(str) }. We may refer to 'k' to as input_group_name in DB terms.
    - outputs: The output files specs. Comprises of specs about the path the output should 
               be saved to and about the handling that should be applied in a metadata level
               (New resource of a referenced dataset, Replacement of an existing resource, Do nothing)
               Partially, this information is propagated to the tool
               defining the destination path of the execution outputs.
    - secrets: A special field that contains sensitive information which is required by the tool
               but should not be accessible to anyone other than the creator user. (Visible upon
               signing of the request using special generated signature).
    - image: The docker image, already pushed to the STELAR embedded registry, used to
             execute the tool and handle the input/output handling to/from it.
            
    Note that not all parameters are exclusively required to execute every Task. Each tool 
    is unique and requires custom configuration for execution.

"""


class TaskInputSchema(Schema):
    pass


class TaskOutputSchema(Schema):
    pass


class TaskDatasetSchema(Schema):
    pass


# Besides the state, all other params are dump_only
class TaskSchema(Schema):
    "Schema for creation, read and update of a Task Entity"

    class Meta:
        datetimeformat = "iso"

    id = fields.UUID(dump_only=True)
    process_id = fields.UUID(required=True)
    secrets = fields.Dict(values=fields.Raw(), allow_none=True, required=False)
    inputs = fields.Dict(values=fields.Raw(), required=False)
    outputs = fields.Dict(values=fields.Raw(), required=False)
    datasets = fields.Dict(values=fields.Raw(), required=False)
    parameters = fields.Dict(required=False, values=fields.Raw(), allow_none=True)
    name = fields.String(required=True)
    # Limit the execution ability only to internally stored images in the STELAR registry.
    # TODO: The registry domain should be populated by an appropriate environment variable.
    image = fields.String(
        required=False,
        allow_none=False,
        validate=lambda value: re.match(
            r"^img\.stelar\.gr/stelar/[a-zA-Z0-9_-]+:[a-zA-Z0-9._-]+$", value
        ),
    )
    exec_state = fields.String(
        validate=validators.OneOf(["running", "failed", "succeeded"]),
        dump_only=True,
        required=False,
    )
    creator = fields.String(dump_only=True)
    start_date = fields.DateTime(dump_only=True)
    end_date = fields.DateTime(dump_only=True, allow_none=True)
    tags = fields.Dict(
        keys=fields.String, values=fields.String(), required=False, allow_none=True
    )


class Task(Entity):
    def __init__(self):
        super().__init__(
            "task",
            "tasks",
            TaskSchema(),
            TaskSchema(partial=True),
        )
        self.operations.remove("update")

    def list(
        self,
        process_id: uuid.UUID,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ):
        """Return the tasks of a given process by providing the ID of it."""

        sql_utils.workflow_get_tasks(process_id)

    def validate_task(self, id: uuid.UUID):
        """Check that the ID provided is an existing Task.

        Args:
            id : The ID of the Task for which the existence is validated.

        Returns:
            The ID of the Task if it exists.

        Raises:
            NotFoundError if the Task does not exist
        """
        task = sql_utils.task_execution_read(id)
        if task:
            return task["task_id"]
        else:
            raise NotFoundError(str(id))

    def generate_signature(self, id):
        """Generates a signature for a given task_id by salting it with the secret key of the flask app
        and hashing it with SHA256.

        Args:
            id: The id of the Task for which the signature will be generated.
        Raises:
            RuntimeError: If the secret key is not properly set for the server.
        """
        secret_key = current_app.secret_key

        if not secret_key:
            raise RuntimeError("Secret key is not set in the Flask app.")

        # Salting the task_id with the secret key and encrypting it.
        salted_task_id = id + secret_key
        return hashlib.sha256(salted_task_id.encode()).hexdigest()

    def verify_signature(self, id, signature):
        """Verifies the signature of a given Task ID by comparing it with the
           signature generated using the secret key of the flask app.

        Args:
            id: The id of the Task for which we want to validate its signature
            signature: The signature under examination

        Returns:
            boolean: Is signature valid
        Raises:
            RuntimeError: If the secret key is not properly set for the server.
        """
        return signature == self.generate_signature(id)

    def get(self, id):
        """Reads the metadata of a task if it exists.

        This method invokes sql_utils methods to structure a
        verbose representation of a task by its ID.

        Args:
            id: The UUID of the task
        Return:
            The Task representation
        Raises:
            NotFoundError: If the Task does not exist
        """
        # Check that the tasks exists and we may fetch it.
        self.validate_task(id)

        task = sql_utils.task_execution_read(id)

        # Delegate some specific tags as top-level attributes in the final repr.
        if task["tags"]:
            if task["tags"].get("tool_image"):
                task["tool_image"] = task["tags"]["tool_image"]
            if task["tags"].get("tool_name"):
                task["tool_name"] = task["tags"]["tool_name"]

        if task["state"] in ["failed", "succeeded"]:
            task["messages"] = task["tags"]["log"]
            task["output"] = sql_utils.task_execution_read_outputs_sql(id)
            task["metrics"] = sql_utils.task_execution_metrics_read_sql(id)
        return task

    def update(self, id, update_attr):
        raise NotAllowedError(
            "Task update is not supported. Tasks are updated by patch only."
        )

    def set_exec_state(self, id, state):
        # Validate the current state of the Task to allow
        # changes only if it is running.
        task = self.get_entity(id)

        if task["exec_state"] == state:
            return
        if task["exec_state"] == "running" and state in ["failed", "succeeded"]:
            end_date = datetime.now()
            sql_utils.task_execution_update(id, state, end_date)
        else:
            raise ConflictError(
                "Exec state can only change from running to failed or succeeded."
            )

    def delete(self, id, purge=False):
        """Deletes a task by its ID if it exists

        Args:
            id: The UUID of the Task to delete.
        Raises:
            ConflictError: If a running Task was attempted to be deleted.
            NotFoundError: If a Task with the given ID is not found.
        """
        task = self.get_entity(id)
        if task["exec_state"] == "running":
            raise ConflictError("Cannot delete a running task.")
        with transaction():
            sql_utils.task_execution_delete(id)

    def parse_inputs(self, id: uuid.UUID, process_id: uuid.UUID, inputs: dict):
        """Parses the input provided in the Task Spec

        It is highly recommended to use this method within a 'transaction()' context
        to ensure that the inputs are inserted in the database in a consistent manner.

        The input spec is a field in the broader JSON that describes the Task.
        It is a nested dictionary with the following structure:

        "inputs": {
            "myinput0": [
                       "6a909646-9218-4e75-902d-0cbef791bc3e",
                       "11b5d161-d6e6-4d3a-beaa-873cd3e74e0c::relation_filter",
                       "s3://klms-bucket/klms/data",
                      ]
            "myinput1": [
                        "11b5d161-d6e6-4d3a-beaa-873cd3e74e0c",
                        "s3://klms-bucket/data/*",
                        "ctx::relation_filter",
                      ]
        }

        Each artifact can be:

        1. Resource UUID: A reference to a resource in the Catalog. Each entry
                          one is translated to the resource
        2. Dataset UUID (UUID::filter): A reference to a dataset in the Catalog. Each entry is
                         expanded to the dataset resource paths. If filter is provided,
                         the resources are filtered accordingly with respect to their
                         relation to the dataset.
        3. Context (ctx::filter):  A reference to the Process package the Task belongs to.
                                   Treated in the same way as a dataset UUID.

        4. Plain URL:  A URL of the form 'protocol://hostname[:port]/path'. Wildcards for S3
                       paths are also supported (s3://klms-bucket/data/*).
                       The wildcards are unfolded during the generation of the input destined
                       to reach the actual tool runtime.
        5. Task Dataset (name::filter): A friendly name of a dataset that is part of the Task.
                          The dataset is validated to exist in the Task and its resources are
                          expanded to the input list upon filter.
        Args:
            id: The ID of the newly created Task.
            process_id: The ID of the process the task belongs to.
            inputs: The inputs of the task as provided in the Task Spec.
        """
        for group in inputs:
            # Maintain a list of resources to be inserted in the database as
            # inputs of the task
            input_artifacts = list()

            for val in inputs[group]:
                artifact_uuid, filter_value = None, None
                # Extract possible filter from val
                if "::" in val:
                    artifact_uuid, filter_value = val.split("::", 1)

                # Check if the input value corresponds to an artifact from the Catalog,
                # a plain path or a reference to the 'Process' package (ctx).
                if is_valid_uuid(artifact_uuid or val):
                    if cutils.is_package(artifact_uuid or val):
                        # Pass dataset_uuid and filter_value to get_package_resources
                        # to fetch resources matching the query.
                        # TODO: DPETROU: Consider changing this to DATASET.get_entity
                        # to align it with the authorization model. This requires a
                        # cascading permission set initiating from 'task_create'.
                        dataset_resources = [
                            resource["id"]
                            for resource in cutils.get_package_resources(
                                artifact_uuid or val, filter_value
                            )
                        ]
                        input_artifacts.extend(dataset_resources)

                    elif cutils.is_resource(artifact_uuid or val):
                        input_artifacts.append(artifact_uuid or val)

                elif re.match(r"ctx(::.*)?", artifact_uuid or val):
                    # Handle the special case of 'ctx' which refers to the 'Process' package
                    # the task belongs to. Validate the existence and type of package first.
                    PROCESS.validate_process(process_id)

                    # Fetch the resources of the 'Process' package and append them to the input list.
                    process_resources = [
                        resource["id"]
                        for resource in cutils.get_package_resources(
                            process_id, filter_value
                        )
                    ]
                    input_artifacts.extend(process_resources)

                elif is_valid_url(val):
                    # We delegate URLs that are not referenced by the Catalog.
                    # Acceptable URLs are of the form 'protocol://hostname[:port]/path'
                    # Wildcard support is also provided for S3 paths (s3://bucket/klms/data/*)
                    # The wildcards are unfolded during the generation of the input spec destined
                    # to the tool.
                    input_artifacts.append(val)

                elif self.dataset_exists(id, artifact_uuid or val):
                    # Handle the case where the value is a dataset friendly name
                    # and the dataset exists in the Task.
                    package = sql_utils.task_read_dataset(id, artifact_uuid or val)
                    if package and package.get("package_uuid") is not None:
                        package_resources = [
                            resource["id"]
                            for resource in cutils.get_package_resources(
                                package.get("package_uuid"), filter_value
                            )
                        ]
                    input_artifacts.extend(package_resources)

            # Insert the input artifacts in the database. Exception or errors are
            # catched through the 'transaction' context of the caller function.
            sql_utils.task_execution_insert_input(id, input_artifacts, group)

    def dataset_exists(self, id: uuid.UUID, dataset_friendly_name: str):
        """Check if the dataset friendly name is a valid Task dataset
           and already exists.

        Args:
            id: The ID of the Task by which the dataset is referenced
            dataset_friendly_name: The friendly name of the dataset to validate.

        Returns:
            True if the dataset exists, False otherwise.
        """
        package = sql_utils.task_read_dataset(id, dataset_friendly_name)

        if package and package.get("package_uuid") is not None:
            return True

        return False

    def validate_dataset(self, id: uuid.UUID, dataset_friendly_name: str):
        """Check if the dataset friendly name is a valid Task dataset
           and referenced in the 'datasets' field.

        Args:
            id: The ID of the Task by which the dataset is referenced
            dataset_friendly_name: The friendly name of the dataset to validate.

        Returns:
            True if the dataset is correctly referenced at 'datasets', False otherwise.
        """
        package = sql_utils.task_read_dataset(id, dataset_friendly_name)

        if package and (
            package.get("package_uuid") is not None
            or package.get("package_details") is not None
        ):
            return True

        return False

    def parse_parameters(self, id: uuid.UUID, parameters: dict):
        """Parses the parameters provided in the Task Spec

        It is highly recommended to use this method within a 'transaction()' context
        to ensure that the parameters are inserted in the database in a consistent manner.

        The parameters spec is a field in the broader JSON that describes the Task.
        It is a dictionary with the following structure:

        "parameters": {
            "param0": "value0",
            "param1": 1234,
            "param2": {
                "key1": "value1",
                "key2": 1234
            },
        }

        Args:
            id: The ID of the newly created Task.
            parameters: The parameters of the task as provided in the Task Spec.
        """
        sql_utils.task_execution_insert_parameters(id, parameters)

    def parse_datasets(self, id: uuid.UUID, datasets: dict):
        """Parses the datasets provided in the Task Spec

        It is highly recommended to use this method within a 'transaction()' context
        to ensure that the datasets are inserted in the database in a consistent manner.

        The datasets spec is a field in the broader JSON that describes the Task.
        It is a dictionary with the following structure:

        "datasets": {
            "dataset0": "6a909646-9218-4e75-902d-0cbef791bc3e",
            "dataset1": {
                "name": "dataset1",
                "title": "Title of the dataset",
                "tags": ["tag1", "tag2"],
                "spatial": {"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [0, 1], [0, 0]]]},
            }
        }

        Datasets can be referenced in other places of the Task Spec using their friendly name.
        Mainly in the inputs and outputs specs.

        Args:
            id: The ID of the newly created Task.
            datasets: The datasets of the task as provided in the Task Spec.
        """

        for dataset, value in datasets.items():
            # Handle the case where the value is a package_id
            if is_valid_uuid(value) and cutils.is_package(value):
                sql_utils.task_execution_insert_future_package_existing(
                    task_exec_id=id,
                    package_id=value,
                    package_friendly_name=dataset,
                )
            # Handle the case where the value is a package_dict
            elif utils.is_valid_package_dict(value):
                encoded_details = utils.encode_to_base64(value)
                sql_utils.task_execution_insert_future_package_details(
                    task_exec_id=id,
                    package_details=encoded_details,
                    package_friendly_name=dataset,
                )

    def parse_outputs(self, id: uuid.UUID, outputs: dict):
        """Parses the output provided in the Task Spec

        It is highly recommended to use this method within a 'transaction()' context
        to ensure that the outputs are inserted in the database in a consistent manner.

        The output spec is a field in the broader JSON that describes the Task.
        It is a dictionary with the following structure:

        "outputs": {
            "output0": {
                "url": "s3://klms-bucket/klms/data.txt",
                "resource": "6a909646-9218-4e75-902d-0cbef791bc3e",
            },
            "output1": {
                "url": "s3://klms-bucket/klms/data.json",
                "dataset": "dataset1",
                "resource": {
                    "name": "Entity Matching Experiment Result 1",
                    "relation": "owned"
                }
            },
            "output2": {
                "url": "s3://klms-bucket/klms/log.txt"
            }
        }

        Each of the outputs specs define:
            1. The URL where the output should be saved.
            2. The way and the dataset where the output should be saved as a resource (if so specified)

        Args:
            id: The ID of the newly created Task.
            outputs: The outputs of the task as provided in the Task Spec.
        """
        for output, spec in outputs.items():
            if isinstance(spec, dict):
                url = spec.get("url")
                if not url:
                    raise DataError(
                        "Output spec must contain a URL as an output path for file: "
                        + output
                    )
                resource = spec.get("resource")
                if resource:
                    if is_valid_uuid(resource):
                        sql_utils.task_execution_insert_output_spec_existing_resource(
                            task_exec_id=id,
                            output_name=output,
                            output_address=url,
                            resource=resource,
                            resource_action=spec.get("resource_action", "REPLACE"),
                        )
                    elif isinstance(resource, dict) and spec.get("dataset"):
                        dataset_friendly_name = spec.get("dataset")
                        if self.validate_dataset(id, dataset_friendly_name):
                            sql_utils.task_execution_insert_output_spec_new_resource(
                                task_exec_id=id,
                                output_name=output,
                                output_address=url,
                                dataset_friendly_name=dataset_friendly_name,
                                resource_name=resource.get("name", ""),
                                resource_label=resource.get("label", ""),
                            )
                        else:
                            raise ConflictError(
                                f"Dataset friendly name `{dataset_friendly_name}` not found in declared datasets."
                            )
                else:
                    sql_utils.task_execution_insert_output_spec_plain_path(
                        task_exec_id=id, output=output, url=url
                    )

    def create_task(self, creator_user: str, token: str, **spec):
        """Creates a new Task under a Process according to spec

        Args:
            creator_user: The username of the user creating the Task
            spec: The JSON describing the specs of the Task to create.

        Raises:
            NotFoundError: If the Process is not found
        """
        process_id = str(spec.get("process_id"))
        inputs = spec.get("inputs")
        outputs = spec.get("outputs", {})
        datasets = spec.get("datasets")
        secrets = spec.get("secrets")
        parameters = spec.get("parameters")
        tags = spec.get("tags", {})
        image = spec.get("image")

        # Validate the process existence
        PROCESS.validate_process(process_id)

        # Validate the state of the process, as only running processes may accept tasks
        if PROCESS.get_entity(process_id).get("exec_state") != "running":
            raise ConflictError(
                f"Process '{process_id}' is not running and it may not accept tasks"
            )

        # Generate the ID and start date of the Task under creation
        sdate = datetime.now().isoformat()
        task_id = str(uuid.uuid4())

        # Store the name and image of the task in the tags table.
        if "name" in spec:
            tags["name"] = spec["name"]
        if "image" in spec:
            tags["image"] = spec["image"]

        # Act within a transaction to ensure that the task is created in a consistent manner.
        # Avoid partial creation of the task in the database leading to inconsistencies.
        with transaction():
            # Create the execution of the task in the database
            sql_utils.task_execution_create(
                task_id, process_id, sdate, "created", creator_user, tags
            )

            # Clear the tags to avoid future conflicts
            tags = {}

            # Parse the datasets. Performs insertion in the database, failures
            # handled by the transaction context.
            self.parse_datasets(task_id, datasets)

            # Parse the inputs. Performs insertion in the database, failures
            # handled by the transaction context.
            self.parse_inputs(task_id, process_id, inputs)

            # Parse the params. Performs insertion in the database, failures
            # handled by the transaction context.
            self.parse_parameters(task_id, parameters)

            # Insert possible secrets in the database. Exception or errors are
            # catched through the 'transaction' context.
            sql_utils.task_execution_insert_secrets(task_id, secrets)

            # Insert the output specs in the database. Exception or errors are
            # catched through the 'transaction' context.
            self.parse_outputs(task_id, outputs)

            # If the task is to be executed in the cluster, create the task execution
            # on the engine and store the container_id and job_id in the database as task tags.
            if image:
                engine = execution.exec_engine()
                token = "Bearer " + token
                task_signature = self.generate_signature(task_id)
                tags["container_id"], tags["job_id"] = engine.create_task(
                    image, token, task_id, task_signature
                )

                sql_utils.task_execution_update(task_id, "running", tags=tags)

            return {
                "id": task_id,
                "job_id": tags.get("job_id", "__external__"),
                "signature": self.generate_signature(task_id),
            }

    def create(self, init_data):
        """Creates a new Task under a Process according to spec"""
        return self.create_task(
            kutils.current_user().get("username"), kutils.current_token(), **init_data
        )

    def patch(self, id: uuid, state):
        """Patches the current state of an existing Task.
        Allows, for the time being, updating the state of the task to 'succeeded' or 'failed'.
        Other fields of the task are immutable or not patchable.

        Keyword arguments:
            state: The new state of the task. One of 'succeeded', 'failed'.
        Raises:
            NotFoundError: If the task is not found.
        """
        # Fetch the task and update its state.
        task = self.get_entity(id)
        self.set_exec_state(task["id"], state)

    def delegate_input_artifacts(
        self, id: uuid.UUID, inputs: dict, credentials: dict = None
    ):
        """
        Delegate the input artifacts to the appropriate URLs
        based on their type. Supports translating wildcard paths
        from S3 to their actual paths (limited to paths with s3://)

        Args:
            id: The ID of the Task
            inputs: The inputs of the Task as fetched from the database
        Returns:
            A dictionary with the input artifacts delegated to their URLs
            organized by the input group name.
        """

        # Delegate the input artifacts to the appropriate URLs
        # based on their type.
        delegated_inputs = {}
        for input_group in inputs:
            delegated_inputs[input_group] = []
            for artifact in inputs[input_group]:
                if is_valid_uuid(artifact):
                    # Fetch the resource path from the Catalog
                    artifact = cutils.RESOURCE.get_entity(artifact)["url"]
                    if artifact:
                        # If we have access to the data layer through the user's credentials
                        # we unfold wilcard paths for S3 URLs to their actual paths.
                        if credentials:
                            if (
                                isinstance(artifact, str)
                                and artifact.startswith("s3://")
                                and artifact.endswith("/*")
                            ):
                                expanded_paths = expand_wildcard_path(
                                    artifact, credentials=credentials
                                )
                                if expanded_paths:
                                    delegated_inputs[input_group].extend(expanded_paths)
                                    continue

                        delegated_inputs[input_group].append(artifact)
                elif is_valid_url(artifact):
                    # Delegate the URL as is
                    delegated_inputs[input_group].append(artifact)
        return delegated_inputs

    def get_input(self, id: uuid.UUID, token: str = None, signature: str = None):
        """Fetches the input spec of a Task including inputs, outputs and params.

        The spec is provided in a dictionary format and includes the inputs, outputs
        and parameters of the Task. The inputs are delegated to the appropriate URLs
        based on their type. The final product is a dictionary of input groups that
        contain the URLs of the artifacts. Wildcard paths for S3 URLs are unfolded
        to their actual paths if the user has access to the data layer through the
        provided credentials.

        The method also verifies the signature of the request to include secret information
        if the signature is valid. Signature is generated on task creation time.

        An example of the input spec is as follows:

        {
            "inputs": {
                "group1": [
                    "s3://bucket/path/to/object",
                    "s3://bucket/path/of/object"
                ]
            },
            "outputs": {
                "file1": "s3://bucket2/path/to/write",
                "file2": "s3://bucket2/path/to/output"
            },
            "parameters: {
                depth: 14,
                keyword: "foo",
            },
            "minio": {
                "endpoint_url": "https://minio.stelar.gr",
                "id": "ACCESS_KEY",
                "skey": "SECRET_KEY",
                "stoken": "SESSION_TOKEN"
            },
            "secrets": {
                "openai_key": "API_KEY",
            }
        }

        Args:
            id: The ID of the Task
            token: The token of the actor user
            signature: The signature of the request to include secret information

        Returns:
            A dictionary with the input spec of the Task including the inputs, outputs and parameters.

        Raises:
            NotFoundError: If the Task is not found.
        """

        self.validate_task(id)
        id = str(id)

        # Fetch the input groups and the parameters for the task execution from the database
        inputs = sql_utils.task_execution_input_read_sql(id)
        parameters = sql_utils.task_execution_parameters_read_sql(id)

        credentials = None
        if token:
            credentials = get_temp_minio_credentials(token)

        # Delegate the input artifacts to the appropriate URLs
        # based on their type. The final product is a dictionary
        # of input groups that contain the URLs of the artifacts.
        delegated_inputs = self.delegate_input_artifacts(id, inputs, credentials)

        # Read the paths for the output files that the tool is directed to write to.
        outputs = sql_utils.task_read_output_spec(id)

        # Construct the output destined to reach the task runtime
        task_input_spec = {}
        task_input_spec["inputs"] = delegated_inputs if delegated_inputs else {}
        task_input_spec["parameters"] = parameters if parameters else {}
        task_input_spec["outputs"] = outputs if outputs else {}

        # If the request is signed, we verify the signature to include secret information.
        if signature:
            if self.verify_signature(id, signature):
                # Fetch the secrets for the task execution from the database
                secrets = sql_utils.task_execution_read_secrets(id)
                if secrets:
                    secrets_dict = {
                        secret["key"]: secret["value"] for secret in secrets
                    }
                    task_input_spec.update({"secrets": secrets_dict})
                task_input_spec["signature_verified"] = True

        # Fetch the app config to include the MinIO API url.
        config = current_app.config["settings"]

        if credentials:
            # If credentials were generated, propagate them to the
            # task input spec to allow the tool to access the data layer.
            task_input_spec["minio"] = {
                "endpoint_url": config["MINIO_API_EXT_URL"],
                "id": credentials["AccessKeyId"],
                "key": credentials["SecretAccessKey"],
                "skey": credentials["SessionToken"],
            }
        else:
            task_input_spec["minio"] = {"endpoint_url": config["MINIO_API_EXT_URL"]}

        return task_input_spec

    def handle_output_key(self, id: uuid.UUID, key: str, path: str):
        """Handles all scenarios on how to save an output of a Task execution in the data catalog.
        Args:
            id: The ID of the Task
            key: The key of the output
            path: The path where the output was actually saved by the task

        Returns
            The ID of the resource created in the catalog or updated.

        Raises:
            NotFoundError: If a resource tended to be updated does not exist. If a dataset
                            referenced in the output spec does not exist.
        """
        output_spec = sql_utils.task_read_output_spec_of_file(id, key)
        if output_spec:
            # Handle the case where an existing resource should be updated with the new output path of the tool output.
            if output_spec.get("resource_id"):
                cutils.RESOURCE.update_entity(
                    output_spec.get("resource_id"),
                    {
                        "url": path,
                        "name": output_spec.get("resource_name"),
                        "relation": output_spec.get("resource_label"),
                    },
                )
                return output_spec.get("resource_id")

            # Handle the case where a refenence to a dataset is included in the spec
            # and we need to create a new resource in that dataset or also create the dataset itself.
            elif output_spec.get("dataset_friendly_name"):
                # Package does not exist, should be created
                if output_spec.get("package_details"):
                    decoded_package = utils.decode_from_base64(
                        output_spec.get("package_details")
                    )

                    try:
                        package_id = cutils.DATASET.create_entity(decoded_package)["id"]
                    except Exception:
                        # Package already exists
                        # TODO: DPETROU: change this to get_entity of the dataset class
                        package_id = cutils.get_package(
                            id="0", title=decoded_package.get("title")
                        )["id"]

                    res_id = cutils.RESOURCE.create_entity(
                        {
                            "package_id": package_id,
                            "name": output_spec.get("resource_name"),
                            "url": path,
                            "relation": output_spec.get("resource_label"),
                        }
                    )["id"]
                    return res_id

                # Package exists, we should create a resource inside it
                elif output_spec.get("package_uuid"):
                    res_id = cutils.RESOURCE.create_entity(
                        {
                            "package_id": output_spec.get("package_uuid"),
                            "name": output_spec.get("resource_name"),
                            "url": path,
                            "relation": output_spec.get("resource_label"),
                        }
                    )["id"]
                    return res_id

    def save_output(self, id: uuid.UUID, signature: str, **spec):
        """Saves the output of a Task execution in the database upon spec.

        The output spec is a field in the broader JSON that describes the Task
        and is provided during the creation of the Task. Upon this spec the outputs
        provided by the end of the execution are treated.

        Args:
            id: The ID of the Task
            signature: The signature of the Task to validate.
            spec: The JSON describing the outputs generated by the Task and the state
                  it concluded to.


        """
        # The only measure of verification used to ensure the validity of the request
        # is the signature. The signature is generated on task creation time and is
        # used by the Task runtime to publish the output of the execution.
        if not self.verify_signature(id, signature):
            raise AuthorizationError("Invalid Task Signature. Access Denied.")

        # Validate the task existence
        self.validate_task()

        # Parse the output JSON provided in the request
        outputs = spec.get("output", {})
        actual_resource_output = []

        # Handle each output the tool produced in metadata terms i.e. publish
        # appropriately resources in the catalog upon specifications provided
        # during the task creation. We maintain a list of the actual resources
        # the task registered in the catalog.
        # TODO: DPETROU: Consider also registering paths that were generated
        # but have no presence in the catalog.
        for output, path in outputs.items():
            actual_resource_output.append(self.handle_output_key(id, output, path))

        # Register the actual resources registered in the catalog by the task
        if actual_resource_output:
            sql_utils.task_execution_insert_output(id, actual_resource_output)

        # Now handle the metrics, messages and state of the task.
        sql_utils.task_execution_insert_metrics(id, spec.get("status"))
        sql_utils.task_execution_insert_log(id, spec.get("messages"))

        if "error" in spec:
            self.set_exec_state(id, "failed")

        elif spec.get("status"):
            map_state = map_state_to_execution_status(spec.get("status"))
            self.set_exec_state(id, map_state)


# ------------------------------------------
#
# The TASK entity singleton
#
TASK = Task()
#
#
# ------------------------------------------


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


# Map HTTP status codes or other indicators to states
def map_state_to_execution_status(state):
    if isinstance(state, int):  # If state is an HTTP code
        if 200 <= state < 300:  # Success HTTP codes
            return "succeeded"
        else:
            return "failed"
    elif isinstance(state, str):  # If state is a string like "success", "error"
        state = state.lower()
        if state in ["success", "succeeded"]:
            return "succeeded"
        elif state in ["error", "failed"]:
            return "failed"
    # Default to failed for unrecognized states
    return "failed"
