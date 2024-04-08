from airflow.models.baseoperator import BaseOperator
from jinja2 import Template
from airflow.models import Variable
import requests
from time import sleep
import ast


class TaskInitializer(BaseOperator):
    def __init__(self, docker_image, input, parameters, tags, token,
                 **kwargs):
        super().__init__(**kwargs)
        self.docker_image= docker_image
        self.input = input
        self.parameters = parameters
        self.tags = tags
        self.token = token

    def execute(self, context):
        task_id = context['task_instance'].task_id
        url = Variable.get("DATA_API_URL")
        self.token = Template(self.token).render(**context)
        headers = {'Api-Token': self.token}
        print(headers)
        
        for k, v in self.parameters.items():
            if type(v)!=str or not v.startswith('{{'):
                continue
            v = Template(v).render(**context)
            try:
                v = ast.literal_eval(v)
            except:
                v = v
            self.parameters[k] = v
        print(self.parameters)
        
        #TODO: Fix input xcom
        new_input = []
        for input_id in self.input:
            if input_id.startswith('rsc'):
                new_input.append(context['ti'].xcom_pull(key=input_id))
            else:
                new_input.append(input_id)
        
        package_id= context['ti'].xcom_pull(key='package_id')
        workflow_exec_id= context['ti'].xcom_pull(key='workflow_exec_id')
        
        data = {"workflow_exec_id": workflow_exec_id,
                "docker_image": self.docker_image,
                "input": new_input,
                "parameters": self.parameters,
                "package_id": package_id,
                "tags": self.tags}
        print(data)
        response = requests.post(url + 'task/execution/create', 
                                  json=data, headers=headers)
        print(response.json())
        task_exec_id = response.json()['task_exec_id']
        
        # # Track task metadata
        state = 'running'
        while state != 'succeeded' and state != 'failed':
            response = requests.get(url + 'task/execution/read?id=' + task_exec_id, 
                                headers=headers)
            print(response.status_code)
            print(response.json())   
            state = response.json()['result']['metadata']['state']
            sleep(10)
            
        for no, res_id in enumerate(response.json()['result']['output']):
            context['ti'].xcom_push(key=f'rsc:{task_id}_{no}', value=res_id)
