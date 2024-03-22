from airflow.models.baseoperator import BaseOperator
from jinja2 import Template
from airflow.models import Variable
import requests


class WorkflowInitializer(BaseOperator):
    def __init__(self, package_title, package_notes, 
                 package_tags, workflow_tags, token,
                 **kwargs):
        super().__init__(**kwargs)
        self.package_title = package_title
        self.package_notes = package_notes
        self.package_tags = package_tags
        self.workflow_tags = workflow_tags
        self.token = token

    def execute(self, context):
        url = Variable.get("DATA_API_URL")
        self.token = Template(self.token).render(**context)
        
        data = {"package_metadata": {"title": self.package_title,
                                     "notes": self.package_notes,
                                     "tags": self.package_tags}}
        headers = {'Api-Token': self.token}
        response = requests.post(url + 'workflow/publish', 
                                  json=data, headers=headers)
        if response.status_code != 200:
            raise ValueError('Error in creating package to CKAN.')
        j = response.json()
        print(j)
        if not j['success']:
            raise ValueError('Error in creating package to CKAN.')            
        package_id = response.json()['result']['package_id']
        
        context['ti'].xcom_push(key='package_id', value=package_id)
        
        data = {"tags": self.workflow_tags}
        headers = {'Api-Token': self.token}
        response = requests.post(url + 'workflow/execution/create', 
                                  json=data, headers=headers)
        if response.status_code != 200:
            raise ValueError('Error in creating worfklow.')
        j = response.json()
        if not j['success']:
            raise ValueError('Error in creating worfklow.')            
        workflow_exec_id = response.json()['workflow_exec_id']
        
        context['ti'].xcom_push(key='workflow_exec_id', value=workflow_exec_id)
