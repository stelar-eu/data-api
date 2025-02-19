task_request = {
    "workflow_exec_id": "073f8608-8f51-4bb4-9fd5-c7e76bfba517",
    "tool_name": "MapReduce Word Count",
    "docker_image": "petroud/stelar-word-count:latest",
    "datasets": {
        "d2": {
            "title": "RJ Word Count",
            "notes": "Word Count Processes on RJ novel",
            "tags": ["MapReduce", "STELAR", "Word Count"],
        }
    },
    "inputs": {"text_to_count": ["ab839033-f0f3-4be2-b049-2a441a5618da::owned"]},
    "outputs": {
        "word_count_file": {
            "url": "s3://klms-bucket/dimitris_word_count.txt",
            "dataset": "d2",
            "resource": {"name": "Romeo Juliet Word Count Result", "label": "owned"},
        }
    },
    "secrets": {"aws_api_key": "ANAZONAWSAPIKEY"},
    "parameters": {},
}
