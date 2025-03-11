import hashlib
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional

import requests
from apiflask import Schema, fields, validators
from flask import current_app, jsonify
from mutils import get_temp_minio_credentials, expand_wildcard_path
import cutils
import execution
import kutils
import sql_utils
import utils
from backend.ckan import ckan_request
from backend.pgsql import transaction
from entity import Entity, PackageCKANSchema, PackageEntity
from exceptions import (
    BackendLogicError,
    ConflictError,
    DataError,
    InvalidError,
    NotAllowedError,
    NotFoundError,
)
from utils import is_valid_url, is_valid_uuid

logger = logging.getLogger(__name__)


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

    Provides the path to the file (URL, S3 bucket or local file) where an artifact
    (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    # Fetch the app config to gain access to URLs.
    try:
        resource = ckan_request("resource_show", id=resource_id)
        return resource["url"]
    except NotFoundError:
        return None


def get_workflows():
    """Retrieve all workflows."""
    try:
        response = sql_utils.workflow_get_all()
        # return response if response else "No workflows submitted yet."
        return response if response else []
    except Exception as e:
        raise RuntimeError(f"Workflows Could Not Be Retrieved. {e}")


"""
    Workflow Processes:
    ===================

    Are implemented as CKAN packages with a type of 'process', as well as a record in the database.
    The link between the two is the 'id',  stored in 'id' field of CKAN as well as in 'workflow_uuid' column
    in the database.

    Database is responsible for storing the following fields:
    - start_date: The date and time when the process was started.
    - end_date: The date and time when the process was completed.
    - exec_state: The state of the process. Can be 'running', 'failed', 'succeeded'. 
    - creator: The username of the user who created the process.
    - workflow: The UUID of the workflow package, which represents the "abstract workflow"
            of which this process is an instance. Stored in the "wf_package_id" column.
            [TODO: we should probably replace the current 'on delete cascade' with 
            an 'on delete set null' to avoid deleting the workflow process when a workflow 
            is deleted]

    - tasks: A list of task UUIDs that are part of the process.

    Of the above, all are read-only except 'exec_state' which can be updated by the user,
    (albeit, only once, from 'running' to either 'failed' or 'succeeded').
    

    CKAN is responsible for storing the following fields:
    
    Immutable fields:
    - name: The name of the package. It is not necessary to provide one; a default of 'workflow-process-<someuuid>' 
            is used. Note that <someuuid> is a random UUID, NOT THE UUID OF THE PROCESS.
    
    Mutable fields:
    - owner_org: The organization that owns the package. This is a required field.

    - state: The state of the process. Can be 'active', 'deleted'.  Note that, to delete a process, 
            it must either be in 'failed' or 'succeeded' state.

    - title, notes, author, author_email, maintainer, maintainer_email, url, version, tags, extras:
        These are all optional fields that can be provided by the user. They are stored as-is in CKAN.

    - relationships_as_subject, relationships_as_object: also supported.

    - resources: [] supported via packages. Process resources are files that are associated with the process,
            not other datasets.

    Other fields from CKAN are suppressed.

    Note:
    ------

    The database also defines table "klms.workflow_tag" which does not have any use currently. In proper
    workflow engines, a process also has "variables" that change during execution of a process.
    We may want to implement this feature on top this table.
"""


class WorkflowProcessSchema(Schema):
    """Schema for creation and update of Workflow Process entity."""

    class Meta:
        datetimeformat = "iso"

    id = fields.String(dump_only=True)
    metadata_created = fields.DateTime(dump_only=True)
    metadata_modified = fields.DateTime(dump_only=True)
    creator_user_id = fields.String(dump_only=True)
    type = fields.String(dump_only=True)

    # From the database
    creator = fields.String(dump_only=True)
    start_date = fields.DateTime(dump_only=True)
    end_date = fields.DateTime(dump_only=True, allow_none=True)
    exec_state = fields.String(
        validate=validators.OneOf(["running", "failed", "succeeded"])
    )
    workflow = fields.UUID(allow_none=True, load_default=None)

    name = fields.String()
    state = fields.String(validate=validators.OneOf(["active", "deleted"]))
    owner_org = fields.String(required=True)

    # By default, dataset metadata will be publicly available
    private = fields.Boolean(load_default=False)

    tags = fields.List(fields.String)
    extras = fields.Dict()

    title = fields.String()
    # Do we really need these 4?
    # Maybe we should replace them with other specs, like
    # - orchestation engine  (e.g., manual, rapidminer, airflow, argo etc.)
    # - workflow language
    author = fields.String(allow_none=True)
    author_email = fields.String(allow_none=True)
    maintainer = fields.String(allow_none=True)
    maintainer_email = fields.String(allow_none=True)
    # Note: making this a URL would force checks that might fail
    notes = fields.String(validate=validators.Length(0, 10000), allow_none=True)
    url = fields.String(validate=validators.Length(0, 200), allow_none=True)
    version = fields.String(validate=validators.Length(0, 100), allow_none=True)


class ProcessCKANSchema(PackageCKANSchema):
    pass
    # Nothing to add here yet...


class ProcessEntity(PackageEntity):
    def __init__(self):
        super().__init__(
            "process",
            "processes",
            WorkflowProcessSchema(),
            WorkflowProcessSchema(partial=True),
            package_type="process",
            ckan_schema=ProcessCKANSchema(),
        )
        self.operations.remove("update")

    DB_FIELDS = [
        "id",
        "workflow",
        "start_date",
        "end_date",
        "exec_state",
        "creator",
        "tasks",
    ]

    CKAN_FIELDS = [
        "id",
        "type",
        "name",
        "metadata_created",
        "metadata_modified",
        "private",
        "state",
        "owner_org",
        "title",
        "notes",
        "author",
        "author_email",
        "maintainer",
        "maintainer_email",
        "version",
        "url",
        "tags",
        "extras",
        "resources",
        "groups",
    ]

    GET_KEEP_FIELDS = frozenset(CKAN_FIELDS) | frozenset(DB_FIELDS)

    # def list_entities(self, limit=None, offset=None):
    #    self.check_limit_offset(limit, "limit")
    #    self.check_limit_offset(offset, "offset")
    #    result = execSql("SELECT workflow_uuid FROM klms.workflow_execution")
    #    return [row["workflow_uuid"] for row in result]

    def create_process(self, creator_user: str, organization=None, **attributes):
        """Create a new workflow process.

        Creates a new workflow process based on the input parameters provided.
        The workflow process is used to manage and monitor the execution of tasks.
        The workflow process is associated with a package in CKAN and can have additional
        metadata. The workflow acts as a shared context for the tasks belonging to it.

        Args:
            creator: The username of the user who creates the workflow process.
            organization: The organization associated with the workflow process metadata.
            attributes: Additional metadata associated with the workflow process. This includes
                fields for CKAN packages as well as other metadata fields.

        Returns:
            The unique identifiers of the created workflow process and its linked package.
        """

        # Raises an exception if the organization does not exist
        org = cutils.ORGANIZATION.get_entity(organization)

        # Check if the workflow exists and is given as ID (names are also allowed)
        workflow = attributes.get("workflow", None)
        if workflow is not None:
            # This may raise!
            # Note: besides validating the 'workflow' package exists and is of type
            # workflow, we also return the package ID. ('workflow' may refer to a name)
            workflow = self.validate_workflow(workflow)

        # Create the a process name: if given, use it, otherwise generate a random one
        random_uuid = uuid.uuid4()
        package_name = attributes.get("name", f"workflow-process-{random_uuid}")

        owner_org = org.get("id") if org else None
        creator_user_email = (
            creator_user["email"] if creator_user.get("emailVerified") else None
        )
        title = attributes.get("title", f"Workflow Process {random_uuid}")

        # Create the package in CKAN
        package_creation_req = {
            "id": random_uuid,
            "name": package_name,
            "type": "process",  # N.B. this will be ignored until scheming is activated
            "owner_org": owner_org,
            "author": attributes.get("author", creator_user["username"]),
            "author_email": attributes.get("author_email", creator_user_email),
            "maintainer": attributes.get("maintainer", creator_user["username"]),
            "maintainer_email": attributes.get("maintainer_email", creator_user_email),
            "title": title,
        }

        # Add any other fields that don't have defaults
        for pattr in ProcessEntity.CKAN_FIELDS:
            if (
                pattr != "id"
                and pattr not in package_creation_req
                and pattr in attributes
                and attributes[pattr] is not None
            ):
                # Add the attribute to the package creation request
                package_creation_req[pattr] = attributes[pattr]

        # This will raise on failure
        package_creation_req = self.create_to_ckan(package_creation_req)
        package = ckan_request(
            "package_create", json=package_creation_req, context={"entity": "process"}
        )

        package_id = package["id"]
        start_date = datetime.now()
        exec_state = "running"

        # Now, try to create the process in the database
        try:
            sql_utils.workflow_execution_create(
                package_id,
                start_date,
                exec_state,
                creator_user["username"],
                workflow,
                {},
            )
        except Exception:
            # Delete the ckan package if the database part of process creation failed
            ckan_request("dataset_purge", id=package_id)
            raise

        package = super().load_from_ckan(package)
        assert isinstance(package["metadata_created"], datetime)
        package = self._filter_fields_from_ckan(package)

        # Consolidate the object to return
        package |= {
            "creator": creator_user["username"],
            "exec_state": exec_state,
            "workflow": workflow,
            "start_date": start_date,
            "end_date": None,
            "tasks": [],
        }

        return package

    def validate_process(self, process: uuid.UUID):
        """Check that a given ID corresponds to an existing process.

        Args:
            process: The ID of the process to validate.

        Returns:
            The ID if the process exists.
        Raises:
            NotFoundError if the process does not exist
            ValidationError if a package with the given ID exists but
                is not a process package.
        """
        proc = ckan_request(
            "package_show", id=str(process), context={"entity": "process"}
        )
        if proc["type"] == "process":
            return proc["id"]
        else:
            raise DataError("The entity is not a process", process)

    def validate_workflow(self, workflow: str | uuid.UUID):
        """Check that the workflow ID is a valid 'workflow' package.

        Args:
            workflow: The ID or name of the package to validate.

        Returns:
            The ID of the package if it is a valid workflow package.

        Raises:
            NotFoundError if the package does not exist
            ValidationError if the package exists but it is not a workflow
                package

        """
        wfid = str(workflow)
        wf = ckan_request("package_show", id=wfid, context={"entity": "workflow"})
        if wf["type"] == "workflow":
            return wf["id"]
        else:
            raise DataError("The entity is not a workflow.", workflow)

    def create(self, init_attr):
        """Create a new process.

        This method overrides the create_entity method of the CKANEntity class.

        Args:
            init_attr: The initial attributes of the entity to be created.

        Returns:
            The created entity.
        """
        creator = kutils.current_user()
        organization = init_attr.get("owner_org", "stelar-klms")
        if "owner_org" in init_attr:
            del init_attr["owner_org"]
        return self.create_process(creator, organization, **init_attr)

    def _enhance_process_package_from_db(self, package):
        """Enhance a package with additional fields.

        This method overrides the enhance_package method of the CKANEntity class.

        Args:
            package: The package to be enhanced.

        Returns:
            The enhanced package.
        """
        w = sql_utils.workflow_execution_read(package["id"])
        if not w:
            raise BackendLogicError(
                "Process not found in the database, out of sync with data catalog.",
                package["id"],
            )
        tasks = sql_utils.workflow_get_tasks(package["id"])
        package.update(
            creator=w["creator"],
            exec_state=w["exec_state"],
            start_date=w["start_date"],
            end_date=w["end_date"],
            workflow=w["workflow"],
            tasks=tasks,
        )
        return package

    def _filter_fields_from_ckan(self, package):
        return {k: v for k, v in package.items() if k in self.GET_KEEP_FIELDS}

    def load_from_ckan(self, raw_obj):
        obj = super().load_from_ckan(raw_obj)
        process = self._filter_fields_from_ckan(obj)
        process = self._enhance_process_package_from_db(process)
        return process

    def update(self, id, update_attr):
        raise NotAllowedError(
            "Process update is not supported. Processes are updated by patch only."
        )

    UPDATABLE_CKAN_FIELDS = frozenset(
        [
            "title",
            "notes",
            "owner_org",
            "author",
            "author_email",
            "maintainer",
            "maintainer_email",
            "version",
            "url",
            "tags",
            "extras",
            "resources",
        ]
    )

    def patch(self, id: str, patch_attr):
        # Get the process
        process = self.get_entity(id)

        ckan_patch = {}
        db_patch = {}

        # Check for special patching attributes
        for attr, new_value in patch_attr.items():
            match attr:
                case "state":
                    if process["state"] == new_value:
                        continue
                    if new_value not in ["active", "deleted"]:
                        raise InvalidError(
                            message="Validation errors in patch operation.",
                            detail={"state": {"error": "Invalid state."}},
                        )
                    if process["state"] == "deleted" and new_value == "active":
                        ckan_patch["state"] = "active"
                    else:
                        raise ConflictError(
                            "State can only change from deleted to active."
                        )
                case "exec_state":
                    if process["exec_state"] == new_value:
                        continue
                    if process["exec_state"] == "running" and new_value in [
                        "failed",
                        "succeeded",
                    ]:
                        db_patch["exec_state"] = new_value
                    else:
                        raise ConflictError(
                            "Exec state can only change from running to failed or succeeded."
                        )
                case "workflow":
                    if process["workflow"] == new_value:
                        continue
                    if new_value is None:
                        db_patch["workflow"] = None
                    else:
                        wfid = self.validate_workflow(new_value)
                        db_patch["workflow"] = wfid
                case _ if attr in self.UPDATABLE_CKAN_FIELDS:
                    ckan_patch[attr] = new_value
                case _ if attr in self.ALL_FIELDS:
                    raise InvalidError(
                        message="Validation errors in patch operation.",
                        detail={attr: {"error": "Attribute not updatable."}},
                    )
                case _:
                    raise InvalidError(
                        message="Validation errors in patch operation.",
                        detail={attr: {"error": "Attribute not recognized."}},
                    )

        ckan_patch = self.update_to_ckan(ckan_patch, id)

        new_package = ckan_request(
            "package_patch", json=ckan_patch, context={"entity": "process"}, id=id
        )

        # See if the database needs to be updated
        with transaction():
            if "exec_state" in db_patch:
                end_date = datetime.now()
                exec_state = db_patch["exec_state"]
                sql_utils.workflow_execution_update(id, exec_state, end_date)

            if "workflow" in db_patch:
                sql_utils.workflow_execution_update_wf_package(id, db_patch["workflow"])

            new_process = self.load_from_ckan(new_package)

        return new_process

    def delete(self, id, purge=False):
        if purge:
            raise NotAllowedError("Purging is not supported for processes.")
        process = self.get_entity(id)
        if process["state"] == "deleted":
            return
        if process["exec_state"] == "running":
            raise ConflictError("Cannot delete a running process.")
        # Delete the process from CKAN
        ckan_request("package_delete", id=id)
        # TODO: Mark the process as deleted with a tag or something...

    def set_exec_state(self, id, state):
        process = self.get_entity(id)
        if process["exec_state"] == state:
            return
        if process["exec_state"] == "running" and state in ["failed", "succeeded"]:
            end_date = datetime.now()
            sql_utils.workflow_execution_update(id, state, end_date)
        else:
            raise ConflictError(
                "Exec state can only change from running to failed or succeeded."
            )


# ------------------------------------------
#
# The PROCESS entity singleton
#
PROCESS = ProcessEntity()

#
#
# ------------------------------------------


def get_workflow_process(workflow_id):
    """Retrieve the metadata for a workflow process.

    Provides the metadata for a workflow process, including the state, start and end time, and the tags. The metadata is used to monitor the progress of a workflow process.

    Args:
        process_id: The unique identifier of the workflow process.
    Returns:
        A JSON with the metadata for the specified workflow process.
    """
    PROCESS.get_entity(workflow_id)


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
    if sql_utils.workflow_execution_read(workflow_id) is None:
        raise NotFoundError("Workflow does not exist.", workflow_id)

    return sql_utils.workflow_get_tasks(workflow_id)


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
        return signature == generate_task_signature(id)

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
                "signature": generate_task_signature(task_id),
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

    def save_output(self):
        pass

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


# ------------------------------------------
#
# The TASK entity singleton
#
TASK = Task()
#
#
# ------------------------------------------


def update_task_state(task_id, state):
    """Update the state of a task. If the state is
    'failed' or 'succeeded', the end date is also updated
    to the current time.

    Args:
        task_id: The unique identifier of the workflow process.
        state: The new state of the workflow process. ('running', 'failed', 'succeeded')
    Returns:
        A boolean value indicating whether the state was successfully updated.
    Raises:
    """
    if not task_id:
        raise AttributeError("Workflow ID is required.")

    try:
        if get_task_info(task_id) is None:
            raise ValueError("Workflow does not exist.")

        if state in ["failed", "succeeded"]:
            end_date = datetime.now().isoformat()
            response = sql_utils.task_execution_update(task_id, state, end_date)
            if not response:
                return False
        else:
            response = sql_utils.task_execution_update(
                task_id, state, "1970-01-01 00:00:01"
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
    Raises:
        RuntimeError: If the workflow process could not be deleted.
    """
    PROCESS.delete_entity(workflow_id)


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
        d = sql_utils.task_execution_read(task_id)
        if d:
            if d["tags"]:
                if d["tags"].get("tool_image"):
                    d["tool_image"] = d["tags"]["tool_image"]
                if d["tags"].get("tool_name"):
                    d["tool_name"] = d["tags"]["tool_name"]

            state = d["state"]

            if state in ["failed", "succeeded"]:
                d["messages"] = d["tags"]["log"]

                d["output"] = sql_utils.task_execution_read_outputs_sql(task_id)
                d["metrics"] = sql_utils.task_execution_metrics_read_sql(task_id)

            return d
        else:
            raise ValueError("Task does not exist.")
    except ValueError:
        raise
    except Exception as e:
        raise
        # raise RuntimeError(f"Task Metadata Could Not Be Retrieved. {e}")


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

    if not verify_task_signature(task_id, signature):
        raise AssertionError("Invalid Task Signature.")

    if not is_valid_uuid(task_id):
        raise AttributeError("Invalid Task ID provided.")

    if sql_utils.task_execution_read(task_id) is None:
        raise ValueError("Task does not exist.")

    outputs = output_json.get("output", {})
    actual_resource_output = []
    for output in outputs:
        output_url = outputs[output]
        output_spec = sql_utils.task_read_output_spec_of_file(task_id, output)
        if output_spec:
            if output_url == output_spec.get("output_address", ""):
                # Handle the case where an existing resource should be updated with the new output path of the tool output.
                if output_spec.get("resource_id"):
                    updated_metadata = {}
                    if output_spec.get("resource_name"):
                        updated_metadata["name"] = output_spec.get("resource_name")
                    if output_spec.get("resource_label"):
                        updated_metadata["relation"] = output_spec.get("resource_label")
                    updated_metadata["url"] = output_url
                    try:
                        resource = cutils.patch_resource(
                            output_spec.get("resource_id"), updated_metadata
                        )
                        if resource.get("id"):
                            actual_resource_output.append(resource.get("id"))
                    except Exception:
                        pass

                # Handle the case where a refenence to a dataset is included in the spec and we need to create a new resource in that dataset.
                # or also create the dataset itself.
                if output_spec.get("dataset_friendly_name"):
                    # Package does not exist, should be created
                    if output_spec.get("package_details"):
                        try:
                            decoded_package = utils.decode_from_base64(
                                output_spec.get("package_details")
                            )
                            try:
                                new_pkg = cutils.create_package(
                                    basic_metadata=decoded_package
                                )
                            except Exception:
                                # Package already exists
                                new_pkg = cutils.get_package(
                                    id="0", title=decoded_package.get("title")
                                )
                            if new_pkg.get("id"):
                                resource_metadata = {}
                                resource_metadata["name"] = output_spec.get(
                                    "resource_name"
                                )
                                resource_metadata["url"] = output_url
                                resource = cutils.create_resource(
                                    new_pkg.get("id"),
                                    resource_metadata,
                                    output_spec.get("resource_label"),
                                )
                                if resource.get("id"):
                                    actual_resource_output.append(resource.get("id"))
                        except Exception:
                            continue
                    # Package exists, we should create a resource inside it
                    elif output_spec.get("package_uuid"):
                        try:
                            resource_metadata = {}
                            resource_metadata["name"] = output_spec.get("resource_name")
                            resource_metadata["url"] = output_url
                            resource = cutils.create_resource(
                                output_spec.get("package_uuid"),
                                resource_metadata,
                                output_spec.get("resource_label"),
                            )
                            if resource.get("id"):
                                actual_resource_output.append(resource.get("id"))
                        except Exception:
                            continue

    # Register the actual resources registered in the catalog by the task
    if actual_resource_output:
        sql_utils.task_execution_insert_output(task_id, actual_resource_output)

    # Now handle the metrics, messages and state of the task.
    state = output_json.get("status")
    messages = output_json.get("message")
    metrics = output_json.get("metrics")

    if metrics:
        sql_utils.task_execution_insert_metrics(task_id, metrics)

    if messages:
        sql_utils.task_execution_insert_log(task_id, messages)

    if "error" in output_json:
        map_state = "failed"
        sql_utils.task_execution_update(
            task_id, map_state, end_date=datetime.now().isoformat()
        )
    elif state:
        map_state = map_state_to_execution_status(state)
        sql_utils.task_execution_update(
            task_id, map_state, end_date=datetime.now().isoformat()
        )

    return True


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
