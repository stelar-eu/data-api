"""
    _Task Execution Management_

    There are several options for workflow task execution in STELAR.
    At this time, the following options are supported.
    - docker (for minimal deployments)
    - kubernetes (for production)

    The execution engine of choice for a particular deployment is configured
    at startup. Therefore, the rest of the code does not need to worry about
    task execution details.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from execution.engine import ExecEngine, ExecEngineFactory


# Private global variable holds a function/callable for returning
# a new execution engine in the current context.
# This variable is initially NULL but is initialized at startup
def _exec_engine_factory() -> ExecEngine:
    pass


def exec_engine():
    """
    Return the configured execution engine for this deployment.
    It is possible that there are several instances of this object
    (e.g., for different contexts/threads)

    Returns
    -------
    Engine
        an engine appropriate for the current context
    """
    return _exec_engine_factory()


def configure(cfg: dict):
    """
    Called at startup to configure the execution module for this deployment.

    Args:
        cfg (dict): The configuration object
    """
    import logging

    # create the logger for the executor
    logger = logging.getLogger("exec")

    execution_cfg = cfg.get("execution", None)

    fatal_help_log_message = """
    It is compulsory to define the 'execution' field in the config file,
    whose value is an object with at least the 'engine' field set.
    If no task execution is to be configured, the 'engine' field can have 
    the value 'none'.

    For example:
    ```
    execution:
        engine: docker
    ```
    or,
    ```
    execution:
        engine: kubernetes
        namespace: default
    ```
    or,
    ```
    execution:
        engine: none
    ```
"""

    def fatal(msg, from_exc=None):
        logger.fatal("%s %s", msg, fatal_help_log_message)
        raise RuntimeError(msg) from from_exc

    if execution_cfg is None:
        fatal("The configuration does not contain an 'execution' field.")

    try:
        engine = execution_cfg['engine']
    except TypeError as e:
        fatal("The execution field is not an object: %a", e.args)
    except KeyError as e:
        fatal("The execution spec does not specify an engine: %a", e)

    match engine:
        case "docker":
            from . import docker as eng

            fct = eng.configure(cfg)
        case "kubernetes":
            from . import kubernetes as eng

            fct = eng.configure(cfg)

        case "none":
            fct = None

        case _:
            fatal(f"Unknown execution engine: {engine}")

    set_exec_engine_factory(fct)
    return


def set_exec_engine_factory(fct: ExecEngineFactory):
    """Set the current exec_engine factory to the given callable

    Args:
        fct (callable): Callable returning
    """
    global _exec_engine_factory
    if fct is not None:
        _exec_engine_factory = fct
        import logging
        logging.getLogger("exec").info("Established execution engine factory.")
    else:
        _exec_engine_factory = lambda: None
        import logging
        logging.getLogger("exec").warning("There is no execution engine.")


__all__ = ["exec_engine", "configure", "set_exec_engine_factory"]
