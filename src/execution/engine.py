"""
Base class for execution engines. This is used mostly for documentation purposes.

"""
from typing import TYPE_CHECKING, Callable


class ExecEngine:

    def create_task(self, tool_name: str, token: str, task_id: str) -> str:
        """Create a new task execution on this engine.

        NOTE: This api is going to change significantly, it currently reflects
        the pre-alpha code in the data-api service.

        Args:
            tool_name (str): currently the docker image. TODO: this should change
            token (str): the task execution user TODO: this should change
            task_id (str): the uuid-like task id, used in the KG

        Returns:
            str: container id, stored as metadata   TODO: this should change
        """
        pass

    def fetch_task_logs(self, task_id: str) -> dict:
        pass

    def get_task_info(self, task_id: str) -> dict:
        pass

# The following is used to designate the return value of the
# 'configure' functions
if TYPE_CHECKING:
    ExecEngineFactory = Callable[[], ExecEngine]
