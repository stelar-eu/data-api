from airflow.models.baseoperator import BaseOperator
from jinja2 import Template
from airflow.models import Variable
import requests


class WorkflowFinalizer(BaseOperator):
    def __init__(self, state, token,
                 **kwargs):
        super().__init__(**kwargs)
        self.state = state
        self.token = token

    def execute(self, context):
        url = Variable.get("DATA_API_URL")
        self.token = Template(self.token).render(**context)
        
        workflow_exec_id= context['ti'].xcom_pull(key='workflow_exec_id')
        
        data = {"workflow_exec_id": workflow_exec_id,
                "state": self.state}
        headers = {'Api-Token': self.token}
        response = requests.post(url + 'workflow/execution/commit', 
                                  json=data, headers=headers)
        if response.status_code != 200:
            raise ValueError('Error in commiting worfklow.')
        
