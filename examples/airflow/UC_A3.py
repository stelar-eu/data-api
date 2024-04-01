from airflow import DAG
from datetime import datetime
from Workflow_Initializer import WorkflowInitializer
from Task_Initializer import TaskInitializer
from Workflow_Finalizer import WorkflowFinalizer

with DAG(dag_id='Demo_for_UC_A3', start_date=datetime(2024, 3, 15),
         max_active_runs=1, 
         schedule=None,
         owner_links={"azeakis": "mailto:azeakis@athenarc.gr"},
         description='Entity Extraction on food recall incidents, accompanied by Entity Linking to a known entity dictionary.',
         tags=["use-cases", "entity_extraction", "entity_linking", 'Agroknow']
         ) as dag:
    
    # Initialize a workflow execution
    workflow_init = WorkflowInitializer(task_id="workflow_init", owner='azeakis',
                                        package_title= "Test Workflow for UC A3 19",
                                        package_notes= "This workflow performs entity extraction and linking",
                                        package_tags= ["STELAR", "Entity extraction", "Entity linking"],
                                        workflow_tags= {},
                                        token = "{{ params.token }}",)
    
    # Initialize an Entity Extraction task
    entity_extraction = TaskInitializer(task_id="entity_extraction", owner='azeakis',
                                    docker_image= "ner:v3",
                                    input= ["42d9de05-530d-4c87-b2a1-f4a661d637f5"],
                                    parameters= {
                                         "output_file":"test_output",
                                         "text_column":"description",
                                         "product_column":"product",
                                         "csv_delimiter":",",
                                         "keep_food": True,
                                         "N":100,
                                         "prediction_values": {"food":["instafoodroberta"]},
                                         "syntactic_analysis_tool":"spacy"
                                    },
                                    tags= {},
                                    token = "{{ params.token }}",)
    
    # Initialize an Entity Linking Task
    entity_linking = TaskInitializer(task_id="entity_linking", owner='azeakis',
                                 docker_image= "alzeakis/pytokenjoin:v5",
                                    input= [ "rsc:entity_extraction_0",
                                            "dbee0078-f053-404a-b09d-bde29eaf5521"],
                                    parameters= {
                                            "header_left": 0,
                                            "col_id_left": "text_id",
                                            "col_text_left": "phrase",
                                            "col_separator_left": ",",
                                            "col_ground_left": "food product",
                                            "text_separator_left": " ",
                                            "header_right": -1,
                                            "col_id_right": "1",
                                            "col_text_right": "2",
                                            "col_separator_right": ";",
                                            "text_separator_right": " ",
                                            "k": 10,
                                            "delta_alg": "1",
                                            "output_file": "out.csv",
                                            "method": "knn",
                                            "similarity": "jaccard",
                                            "foreign": "foreign"
                                    },
                                    tags= {},
                                    token = "{{ params.token }}",)
    
    # Finalize Workflow
    workflow_finalize = WorkflowFinalizer(task_id="workflow_finalize", owner='azeakis',
                                   state = 'succeeded',
                                   token = "{{ params.token }}",)
    
    workflow_init >> entity_extraction >> entity_linking >> workflow_finalize
