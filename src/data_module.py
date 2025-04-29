import yaml
import kutils as ku
import mutils as mu
import logging
from backend.ckan import ckan_request
from backend.kc import KEYCLOAK_OPENID_CLIENT

logger = logging.getLogger(__name__)


class DataModule():

    def __init__(self, config):
        self.config = self.parse_data_layout(config)
    
    def parse_data_layout(self, config):
        """
        Parse the YAML configuration and initialize data layout.
        
        This method processes the data layout and returns the parsed YAML configuration.
        
        Args:
            config (str): YAML configuration string.
        
        Returns:
            dict: The parsed YAML configuration.
        """
        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(config)
        creates_minio_resources(yaml_content)
        create_catalogue_resources(yaml_content)
        


def create_organization(org_data):
    org_name = org_data.get('name')
    # Create the organization
    new_org = ckan_request("organization_create",name=org_name)
    # Check if the organization has groups/subgroups defined
    groups = org_data.get('groups', [])
    for group in groups:
        # Create groups under the organization. These can be nested.
        new_subgroup = ckan_request("group_create",name=group.get('name'))
        ckan_request("member_create",id=new_org.get('id'),object=new_subgroup.get('id'),object_type='group',capacity=group.get('capacity'))

def create_group(group_data):
    group_name = group_data.get('name')
    # Create the group (or subgroup) with its parent organization and/or parent group
    new_group = ckan_request("group_create",name=group_name)
    # group_id = create_ckan_group(group_name, parent_org=parent_org, parent_group=parent_group)
    # Recursively create any subgroups defined within this group
    subgroups = group_data.get('groups', [])
    for subgroup in subgroups:
        new_subgroup = ckan_request("group_create",name=subgroup.get('name'))
        ckan_request("member_create",id=new_group.get('id'),object=new_subgroup.get('id'),object_type='group',capacity=subgroup.get('capacity'))

def create_catalogue_resources(yaml_content):
    if yaml_content.get("catalogue") is None:
        logger.info("error!!!! No catalogue resources defined in the YAML file")
        return
    
    for item in yaml_content["catalogue"]:
        match item:
            case {"organizations":orgs}:
                for org in orgs:
                    create_organization(org)
            case {"groups":groups}:
                for group in groups:
                    create_group(group)
            case _:
                logger.info("error!!!! Invalid catalogue resource type defined in the YAML file")
                return

def creates_minio_resources(yaml_content):
    logger.info("YAML content loaded successfully")
    logger.info(yaml_content)
    if yaml_content.get("resources") is None:
        logger.info("error!!!! No resources defined in the YAML file")
        return

    try:
        keycloak_openid = KEYCLOAK_OPENID_CLIENT()
        logger.info("Keycloak OpenID initialized successfully")

        token = keycloak_openid.token(grant_type="client_credentials")
        logger.info(token["access_token"])

        credentials = mu.get_temp_minio_credentials(token["access_token"])
        logger.info(credentials)
        logger.info("Temporary MinIO credentials obtained successfully")

        minio_admin = mu.initialize_minio_admin(
            ac_key=credentials["AccessKeyId"],
            sec_key=credentials["SecretAccessKey"],
            token=credentials["SessionToken"],
        )

        resources_list = []

        for res in yaml_content["resources"]:
            for buck in res["subfolders"]:
                res_dict = {
                    "bucketname": res["name"],
                    "subfolders": res["subfolders"],
                }
            resources_list.append(res_dict)

        for item in resources_list:
            mu.create_bucket_and_subfolders(minio_admin, item)

    except yaml.YAMLError as e:
        logger.info({"error": "Failed to parse YAML", "details": str(e)})