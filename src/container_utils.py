import docker

def create_container(docker_image, token, api_url, task_exec_id):
    client = docker.from_env()
    container = client.containers.run(
        docker_image,  # Image name
        [token, api_url, task_exec_id],
        # volumes={logdir: {'bind': '/app/logs/', 'mode': 'rw'}},
        detach=True
    )
    
    return container.id