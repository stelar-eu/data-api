import logging
import uuid
from datetime import datetime

from apiflask import Schema, fields, validators
import cutils
import kutils
import sql_utils
from backend.ckan import ckan_request
from psycopg2 import sql
from backend.pgsql import transaction, execSql
from entity import PackageCKANSchema, PackageEntity
from exceptions import (
    BackendLogicError,
    ConflictError,
    DataError,
    InvalidError,
    NotAllowedError,
    NotFoundError,
)

logger = logging.getLogger(__name__)


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
    organization = fields.Dict(dump_only=True)

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
        "organization",
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
            "type": "process",
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

    def build_process_graph(self, id):
        """Return a simplified graph of a workflow execution.

        *Inputs* are now aggregated per package:
            package  ──input(io_name, resources=[…])──►  task

        Args:
            id (str): Workflow-execution UUID (or an object accepted by
                    ``get_entity``).

        Returns:
            dict: ``{"nodes":[…], "edges":[…]}``.
        """
        process = self.get_entity(id)
        workflow_uuid = getattr(process, "workflow_uuid", id)

        # -- helper to absorb tuple- vs dict-rows --------------------------------
        def _get(row, key_or_idx):
            return row[key_or_idx] if isinstance(row, dict) else row[key_or_idx]

        # ------------------------------------------------------------------
        # 1‒ TASKS ----------------------------------------------------------
        # ------------------------------------------------------------------
        sql_tasks = sql.SQL(
            """
            SELECT task_uuid,
                COALESCE(next_task_uuid,'') AS next_uuid,
                state,
                creator_user_id,
                start_date,
                end_date
            FROM {sch}.task_execution
            WHERE workflow_uuid = %s
        """
        ).format(sch=sql.Identifier("klms"))
        tasks_raw = execSql(sql_tasks, [workflow_uuid])

        task_ids = {
            _get(r, "task_uuid" if isinstance(r, dict) else 0) for r in tasks_raw
        }
        tasks_with_time = [
            r for r in tasks_raw if _get(r, "start_date" if isinstance(r, dict) else 4)
        ]
        tasks_without_time = [
            r
            for r in tasks_raw
            if not _get(r, "start_date" if isinstance(r, dict) else 4)
        ]
        tasks_with_time.sort(
            key=lambda r: _get(r, "start_date" if isinstance(r, dict) else 4)
        )
        tasks_ordered = tasks_with_time + tasks_without_time  # final ordered list

        # ------------------------------------------------------------------
        # 1.2‒ TASK TAGS ---------------------------------------------------
        # ------------------------------------------------------------------
        task_tags = {tid: {} for tid in task_ids}  # default empty
        if task_ids:
            sql_tag = sql.SQL(
                """
                SELECT task_uuid, key, value
                FROM {sch}.task_tag
                WHERE task_uuid = ANY(%s)
            """
            ).format(sch=sql.Identifier("klms"))
            tags_raw = execSql(sql_tag, [list(task_ids)])

            for row in tags_raw:
                tid = _get(row, "task_uuid" if isinstance(row, dict) else 0)
                k = _get(row, "key" if isinstance(row, dict) else 1)
                v = _get(row, "value" if isinstance(row, dict) else 2)

                # --- curate key -------------------------------------------
                if k.startswith("__") and k.endswith("__"):
                    k = k[2:-2]  # "__image__" → "image"

                task_tags[tid][k] = v

        # -----------------------------------------------------------------------
        # 2. INPUTS & OUTPUTS ----------------------------------------------------
        # -----------------------------------------------------------------------
        inputs_raw, outputs_raw = [], []
        resource_ids_in, resource_ids_out = set(), set()

        if task_ids:
            sql_in = sql.SQL(
                """
                SELECT task_uuid, resource_id, input_group_name
                FROM {sch}.task_input
                WHERE task_uuid = ANY(%s) AND resource_id IS NOT NULL
            """
            ).format(sch=sql.Identifier("klms"))
            inputs_raw = execSql(sql_in, [list(task_ids)])
            resource_ids_in = {
                _get(r, "resource_id" if isinstance(r, dict) else 1) for r in inputs_raw
            }

            sql_out = sql.SQL(
                """
                SELECT task_uuid,
                    dataset_id  AS resource_id,
                    output_name AS io_name
                FROM {sch}.task_output
                WHERE task_uuid = ANY(%s)
            """
            ).format(sch=sql.Identifier("klms"))
            outputs_raw = execSql(sql_out, [list(task_ids)])
            resource_ids_out = {
                _get(r, "resource_id" if isinstance(r, dict) else 1)
                for r in outputs_raw
            }

        resource_ids_all = resource_ids_in | resource_ids_out

        # -----------------------------------------------------------------------
        # 3. RESOURCES & THEIR PACKAGES -----------------------------------------
        # -----------------------------------------------------------------------
        resources_raw, packages_raw = [], []
        if resource_ids_all:
            sql_res = sql.SQL(
                """
                SELECT id, name, package_id
                FROM public.resource
                WHERE id = ANY(%s)
            """
            )
            resources_raw = execSql(sql_res, [list(resource_ids_all)])

            package_ids = {
                _get(r, "package_id" if isinstance(r, dict) else 2)
                for r in resources_raw
                if _get(r, "package_id" if isinstance(r, dict) else 2)
            }
            if package_ids:
                sql_pkg = sql.SQL(
                    """
                    SELECT id, title
                    FROM public.package
                    WHERE id = ANY(%s)
                """
                )
                packages_raw = execSql(sql_pkg, [list(package_ids)])

        # map resource_id → {name, package_id}
        res_meta = {
            _get(r, "id" if isinstance(r, dict) else 0): {
                "name": _get(r, "name" if isinstance(r, dict) else 1),
                "package_id": _get(r, "package_id" if isinstance(r, dict) else 2),
            }
            for r in resources_raw
        }

        # -----------------------------------------------------------------------
        # 4. COLLAPSE INPUTS BY (package, task, io_name) -------------------------
        # -----------------------------------------------------------------------
        pkg_input_edges = (
            dict()
        )  # key ➜ {"resource_ids": [...], "resource_names":[...]}

        for row in inputs_raw:
            tid = _get(row, "task_uuid" if isinstance(row, dict) else 0)
            rid = _get(row, "resource_id" if isinstance(row, dict) else 1)
            io_name = _get(row, "input_group_name" if isinstance(row, dict) else 2)
            pkg_id = res_meta[rid]["package_id"]  # every resource has one (FK)

            key = (pkg_id, tid, io_name)
            entry = pkg_input_edges.setdefault(
                key, {"resource_ids": [], "resource_names": []}
            )
            entry["resource_ids"].append(rid)
            entry["resource_names"].append(res_meta[rid]["name"])

        # -----------------------------------------------------------------------
        # 5. BUILD NODES ---------------------------------------------------------
        # -----------------------------------------------------------------------
        nodes = {}

        # task nodes
        task_inputs, task_outputs = {tid: set() for tid in task_ids}, {
            tid: set() for tid in task_ids
        }
        for row in inputs_raw:
            task_inputs[_get(row, "task_uuid" if isinstance(row, dict) else 0)].add(
                _get(row, "input_group_name" if isinstance(row, dict) else 2)
            )
        for row in outputs_raw:
            task_outputs[_get(row, "task_uuid" if isinstance(row, dict) else 0)].add(
                _get(row, "io_name" if isinstance(row, dict) else 2)
            )
        for row in tasks_raw:
            tid = _get(row, "task_uuid" if isinstance(row, dict) else 0)
            state = _get(row, "state" if isinstance(row, dict) else 2)
            creator = _get(row, "creator_user_id" if isinstance(row, dict) else 1)
            start_date = _get(row, "start_date" if isinstance(row, dict) else 3)
            end_date = _get(row, "end_date" if isinstance(row, dict) else 4)
            nodes[tid] = {
                "id": tid,
                "type": "task",
                "label": f"{task_tags.get(tid, {}).get('name', '')}",
                "state": state,
                "creator": creator,
                "start_date": start_date,
                "end_date": end_date,
                "inputs": sorted(task_inputs[tid]),
                "outputs": sorted(task_outputs[tid]),
                "tags": task_tags.get(tid, {}),  # <-- NEW
            }

        # package nodes (needed for collapsed inputs **and** for any output-packages)
        for r in packages_raw:
            pid = _get(r, "id" if isinstance(r, dict) else 0)
            ttl = _get(r, "title" if isinstance(r, dict) else 1)
            nodes[pid] = {
                "id": pid,
                "type": "package",
                "label": ttl or f"Package {pid[:8]}…",
            }

        # resource nodes **only** for OUTPUTS (to keep clutter down)
        for rid in resource_ids_out:
            meta = res_meta[rid]
            nodes[rid] = {
                "id": rid,
                "type": "resource",
                "label": meta["name"] or f"Resource {rid[:8]}…",
                "package_id": meta["package_id"],
            }

        # -----------------------------------------------------------------------
        # 6. EDGES ---------------------------------------------------------------
        # -----------------------------------------------------------------------
        edges, seen = [], set()

        def add_edge(src, tgt, rel, io_name="", extra=None):
            key = (src, tgt, rel, io_name)
            if key not in seen:
                seen.add(key)
                e = {"source": src, "target": tgt, "relation": rel}
                if io_name:
                    e["io_name"] = io_name
                if extra:
                    e.update(extra)
                edges.append(e)

        # (A) sequence edges by chronological start_date
        for prev, nxt in zip(tasks_ordered, tasks_ordered[1:]):
            add_edge(
                _get(prev, "task_uuid" if isinstance(prev, dict) else 0),
                _get(nxt, "task_uuid" if isinstance(nxt, dict) else 0),
                "sequence",
            )

        # (B) package → task (collapsed inputs)
        for (pkg_id, tid, io_name), data in pkg_input_edges.items():
            add_edge(
                pkg_id,
                tid,
                "input",
                io_name,
                extra={
                    "resource_ids": data["resource_ids"],
                    "resource_names": data["resource_names"],
                },
            )

        # (C) outputs (task → resource)
        for row in outputs_raw:
            add_edge(
                _get(row, "task_uuid" if isinstance(row, dict) else 0),
                _get(row, "resource_id" if isinstance(row, dict) else 1),
                "output",
                _get(row, "io_name" if isinstance(row, dict) else 2),
            )

        # (D) package → resource
        for rid in resource_ids_out:
            add_edge(res_meta[rid]["package_id"], rid, "member_of")

        return {"nodes": list(nodes.values()), "edges": edges}


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
