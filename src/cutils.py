import requests
from flask import current_app
import re
import json
import utils
from urllib.parse import urljoin, urlencode

from routes.users import api_user_editor
from datetime import datetime


def create_CKAN_headers(API_TOKEN):
    """Create the headers required for publishing a package or a resource in CKAN.

    Args:
        API_TOKEN (string): The API_TOKEN issued by CKAN that is required to establish connection and submit the request.

    Returns:
        Two JSON obejcts: (i) headers for package and (ii) headers for resource.
    """

    package_headers = {'Authorization': API_TOKEN, 'Content-Type': 'application/json'}
    resource_headers = { 'X-CKAN-API-Key': API_TOKEN }
    return package_headers, resource_headers


def request(method, entity_type, endpoint, params=None, data=None, headers=None, json=None, files=None):        
        """
        Sends a request to the CKAN API

        Args:
            method (str): The HTTP method ('GET', 'POST', 'PUT', 'DELETE').
            entity_type (str): The entity type the request intends to handle ('package', 'resource')
            endpoint (str): The API endpoint (relative to `api_url`). Can include query parameters.
            params (dict, optional): URL query parameters.
            data (dict, optional): Form data to be sent in the body.
            headers (dict, optional): Additional request headers.
            json (dict, optional): JSON data to be sent in the body.
            file (file, optional): A file to upload to the request endpoint.

        Returns:
            requests.Response: The response object from the API.
        """
        # Fetch the app config to gain access to URLs.
        config = current_app.config['settings']

        # The base url of the CKAN API endpoint
        # Should be sth like http://ckan:5000/api/3/action/
        api_url = config['CKAN_API']

        # Combine base_url with the endpoint
        endpoint = endpoint.lstrip('/')
        url = urljoin(api_url+"/", endpoint)

        # Handle query parameters in the endpoint or passed as 'params'
        if "?" in endpoint and params:
            raise ValueError("Specify query parameters either in the endpoint or in 'params', not both.")
        
        # If the URL does not contain a query, add parameters from 'params'
        if params:
            url = f"{url}?{urlencode(params)}"
 
        # Prepare headers, defaulting to Authorization if token is present and Content-Type
        default_headers = {}
        package_headers, resource_headers = create_CKAN_headers(config['CKAN_ADMIN_TOKEN'])       

        if entity_type != 'package' and entity_type != 'resource':
            raise AttributeError(f"Entity type '{entity_type}' is not supported!")
        
        default_headers.update(package_headers if entity_type == 'package' else resource_headers)

        if headers:
            default_headers.update(headers)

        # Validate data/json and handle accordingly
        if method.upper() == "GET":
            # GET requests should not have a body (data or json)
            if data or json:
                raise ValueError("GET requests cannot include body data.")
        else:
            # POST, PUT, DELETE, etc., should use either data or json but not both
            if data and json:
                raise ValueError("Specify either 'data' or 'json', not both.")

        # Make the request using the provided method, url, params, data, json, and headers
        response = requests.request(
            method=method,
            url=url,
            params=None,  # params are already incorporated into the URL
            data=data,    # if provided, this will be form data
            json=json,    # if provided, this will be JSON payload
            headers=default_headers,
            verify=True,
            files=files
        )

        # Raise an exception for HTTP errors (4xx, 5xx responses)
        response.raise_for_status()
        return response


def is_package(id: str):
    """Checks if a given ID corresponds a valid existing dataset in CKAN.

    Args:
      id: The ID under examination.
    
    Returns:
        bool: true/false depending to the validity of the ID as package.
    """
    try:
        if id:
            response = request("GET","package","package_show", params={"id": id})
            if response.status_code == 200:
                return True
        else:
            return False
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            return False
        else:
            return False
    except Exception as e:
        return False
        
    
def is_resource(id: str):
    """Checks if a given ID corresponds a valid existing resource in CKAN.

    Args:
      id: The ID under examination.
    
    Returns:
        bool: true/false depending to the validity of the ID as resource.
    """
    try:
        if id:           
            response = request("GET","resource",'resource_show', params={"id":id})
            if response.status_code == 200:
                return True
        else:
            return False
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            return False
    except Exception as e:
        return False
    

def search_packages(keyword: str, limit: int = 0, offset: int = 0, expand_mode: bool = False):
    """
    Search for datasets in the CKAN catalog using a keyword.

    This function interacts with the CKAN API to search datasets in the catalog using
    the `package_search` endpoint. It allows filtering datasets by a keyword and can
    return either basic or detailed package information.

    Args:
        keyword (str): The search keyword to filter datasets.
        limit (int): The number of results to return. If 0, no limit is applied.
        offset (int): The starting point (offset) to fetch the search results from.
        expand_mode (bool): If True, fetch detailed metadata for each dataset.

    Returns:
        list: A list of dictionaries containing package details.

    Raises:
        Exception: If an error occurs while performing the search.

    Example:
        Response: [
            {"id": "dataset_id_1", "name": "Dataset 1", ...},
            {"id": "dataset_id_2", "name": "Dataset 2", ...}
        ]
    """
    try:
        # Validate limit and offset
        if limit < 0 or offset < 0:
            raise ValueError("Limit and offset must be non-negative integers.")
        
        # Prepare query parameters
        params = {
            "q": keyword,
            "start": offset,
            "rows": limit if limit > 0 else 1000,  # Default to a high limit if no limit is specified
        }

        # Make the request to the CKAN API
        response = request("GET", "package_search", params=params)
        
        if response.status_code == 200:
            results = response.json()['result']['results']
            
            if expand_mode:
                # Fetch detailed metadata for sorting or further processing
                detailed_results = []
                for dataset in results:
                    dataset_info = get_package(dataset['id'], include_extras=True, include_resources=True)
                    detailed_results.append(dataset_info)

                return detailed_results
            else:
                # Return basic search results
                return results
        else:
            # Handle error responses from the API
            raise Exception(f"CKAN API returned an error: {response.status_code} - {response.text}")

    except Exception as e:
        # Raise the exception if an error occurs during processing
        raise Exception(f"Error while searching packages: {str(e)}")


def list_packages(limit: int = 0, offset: int = 0, expand_mode: bool = False):
    """
    Retrieve a list of all dataset IDs from the CKAN catalog.

    This function interacts with the CKAN API to fetch the list of all available 
    datasets in the catalog. It calls the `package_list` endpoint, which returns 
    only the unique identifiers (IDs) of the datasets.

    Args:
        limit (int): The number of dataset IDs to return. If 0, no limit is applied.
        offset (int): The starting point (offset) to fetch the dataset IDs from.

    Returns:
        list: A list of dataset IDs if the request is successful.

    Raises:
        Exception: If an error occurs while fetching the dataset list.

    Example:
        Response: ["dataset_id_1", "dataset_id_2", "dataset_id_3"]
    """
    try:
        # Check if no limit is specified or if limit is greater than 0
        if limit == 0:
           pass
        elif limit > 0 and offset >= 0:
           pass
        else:
            raise Exception("Limit must be greater than 0. Offset should be non negative")
        
        # Make the request to the CKAN API using the constructed parameters
        response = request("GET", "package", "package_list")        
        if response.status_code == 200:
            datasets = response.json()['result']
            if expand_mode:
                # Fetch detailed metadata for sorting
                detailed_datasets = []
                for dataset in datasets:
                    dataset_info = get_package(dataset, True, True)
                    detailed_datasets.append(dataset_info)

                sorted_datasets = sorted(
                    detailed_datasets,
                    key=lambda x: datetime.fromisoformat(x['metadata_modified']),
                    reverse=True
                )

                paginated_datasets = sorted_datasets[offset:offset + limit] if limit > 0 else sorted_datasets
                return paginated_datasets
                
            else:
                return datasets
        else:
            return None

    except Exception:
        # If an error occurs during the request, raise a general exception
        raise


def count_packages()->int:
    """
    Returns the number of packages published in the CKAN data catalog
    by looking at the organization parameters. 

    Returns:
        int: The count of packages or 0 if none are registered.

    Raises:
        RuntimeError: In case of error
    """
    try:
        response = request("GET","package","organization_show", params={"id":"stelar-klms", "include_dataset_count":True, "include_users":False})
        if response.status_code == 200:
            resp = response.json()
            org = resp.get('result', None)
            return org.get("package_count", 0)   
        return 0         
    except requests.exceptions.HTTPError as he:
        raise RuntimeError from he


    

def get_packages(limit: int = 0, offset: int = 0, tag_filter: str = None, filter_mode: str = None):
    """
    Retrieve details for multiple datasets, with support for pagination.

    This function calls `list_packages` to get the list of dataset IDs, 
    then fetches details for each dataset using `get_package`.

    Args:
        limit (int): The number of dataset IDs to retrieve (pagination).
        offset (int): The offset point to start retrieving datasets from.
        tag_filter (str):  Apply tag filter according to mode.
        filter_mode (str): Mode of the filter. 'keep' for keeping the matches, 'discard' for discarding the matches

    Returns:
        dict: A dictionary where keys are dataset IDs, and values are the dataset details.

    Example:
        {
            "dataset_id_1": {...dataset details...},
            "dataset_id_2": {...dataset details...}
        }
    """
    # Retrieve a list of dataset IDs using the provided limit and offset
    packages = list_packages(limit=limit, offset=offset)
    
    # If no filtering is required, process all packages
    if not tag_filter or not filter_mode:
        return {package: get_package(package, compressed=True) for package in packages}

    # Process with filtering
    result = {}
    for package in packages:
        pkg = get_package(package, compressed=True)
        # Check if the package matches the filtering criteria
        match_tag = tag_filter in pkg['tags']
        if (filter_mode == 'keep' and match_tag) or (filter_mode == 'discard' and not match_tag):
            result[package] = pkg

    return result


def get_package(id: str, compressed: bool = False, no_resources: bool = False):
    """Retrieve a dataset's details from the CKAN catalog using its unique identifier.

    This function interacts with the CKAN API to fetch metadata about a specific dataset. 
    It is designed to work without requiring authentication, leveraging CKAN's support for 
    unauthenticated GET requests.

    Args:
        id (str): The unique identifier (name) of the dataset to retrieve.
        compressed (bool): Whether to compress the dataset's 'resources' field.

    Returns:
        dict or None: The dataset's details as a dictionary if found, otherwise None.

    Raises:
        ValueError: If the dataset with the specified ID is not found (HTTP 404).
        RuntimeError: For any other HTTP errors encountered while making the request.
    """
    try:
        response = request("GET","package","package_show", params={"id": id})
        if response.status_code == 200:
            resp = response.json()
            dataset = resp.get('result', None)
            
            if dataset:
                dataset['organization'] = dataset['organization']['title']
                
                if no_resources and "resources" in dataset:
                    dataset.pop("resources")

                # Compress resources if compressed flag is True
                if compressed and "resources" in dataset:
                    dataset["resources"] = [
                        {
                            "id": resource.get("id"),
                            "name": resource.get("name"),
                            "url": resource.get("url"),
                            "relation": resource.get("relation")  # Include if present
                        }
                        for resource in dataset["resources"]
                    ]
                
                # Compress tags if compressed flag is True
                if compressed and "tags" in dataset:
                    dataset["tags"] = [tag.get("name") for tag in dataset["tags"]]

                # Compress extras if compressed flag is True
                if compressed and "extras" in dataset:
                    dataset["extras"] = {
                        extra.get("key"): extra.get("value") for extra in dataset["extras"]
                    }
            
            return dataset
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Dataset with ID: {id} was not found")
        else:
            raise RuntimeError from he


def create_package(basic_metadata: dict, extra_metadata: dict = None, profile_metadata: dict = None):
    """This method utilizes the CKAN API to publish a package in the catalog.
    The package published can be defined w/ or w/out resources, w/ or w/out extra metadata
    and w/ or w/out profile metadata. Inside the basic_metadata resources can be defined or not.
    The package that is to be published can have three fields.
    
        Args:
    - basic_metadata: (dict) A dict containing the basic information about the package (name(unique), description, tags etc.)
    - extra_metadata: (dict, optional) Any special metadata such as theme, spatial etc. 
    - profile_metadata: (dict, optional) Any information about an already generated profile that is linked to the package as resource
    
    """    

    ##### Handle the required basic_metadata of the package
    if basic_metadata:
        basic_metadata['name'] = re.sub(r'[\W_]+','_', basic_metadata['title']).lower()
        basic_metadata['tags'] = utils.handle_keywords(basic_metadata['tags'])
       
        resp_org = api_user_editor()
        if resp_org['success']:
            org_json = resp_org['result']
            if len(org_json) > 0:  
                for item in org_json: 
                    if item['type'] == 'organization' and item['state'] == 'active' and item['capacity'] in ('admin','editor'):
                        basic_metadata['owner_org'] = org_json[0]['name']  # CAUTION! Taking the first organization where this user is editor
                        break
        try:                    
            resp_basic = request("POST","package",'package_create', json=basic_metadata)
            if resp_basic.status_code == 200:
                package_id = resp_basic.json()['result']['id']
        except requests.exceptions.HTTPError as he:
            if he.response.status_code == 409:
                raise AttributeError("Package title already exists.")
            else:
                raise RuntimeError from he

    else:
        raise ValueError('No basic metadata provided for publishing in the Catalog. Please specify some basic metadata (title, description, tags, etc.) for the dataset you wish to publish.')
   
    ##### Handle the optional extra_metadata of the package
    if extra_metadata:
        extras = {}
        extras['id'] = package_id 
        extras['extras'] = utils.handle_extras(extra_metadata)
       
        resp_extras = request("POST","package",'package_patch', json=extras)
        if resp_extras.status_code != 200:
            raise RuntimeError(resp_extras.json()['result'])

    ##### Handle the optional profile_metadata of the package
    if profile_metadata != None:
        profile_metadata['package_id'] = package_id   
        if profile_metadata.get('file') != None:
            pass
            # with open(profile_metadata['file'], 'rb') as f:
            #     resp_resource = request("POST","resource",'resource_create', json=resource_metadata, headers=resource_headers, files=[('upload', f)])
            #     arr_resp.append(resp_resource.json())
            #     resource_id = resp_resource.json()['result']['id']
            #     f1 = open(resource_metadata['file'])
            #     profile = json.load(f1)
            #     sql_commands = utils.extractProfileProperties(resource_id, profile)
            #     for sql in sql_commands:
            #         utils.execSql(sql)
        elif profile_metadata.get('url') != None:
            profile_metadata['relation'] = 'profile'
            resp_resource = request("POST","resource",'resource_create', json=profile_metadata)
            if resp_resource.status_code != 200:
                raise RuntimeError(resp_extras.json()['result'])
        else:
            raise ValueError('No profile metadata were associated with this dataset in the Catalog. Please provide a path or a publicly accessible URL where this file is available.')
    

    ##### Return the newly created package by fetching it from the catalog
    new_package_resp = request("GET","package","package_show",params={'id':package_id})

    if new_package_resp.status_code == 200:
        return new_package_resp.json()['result']
    else:
        raise RuntimeError(new_package_resp.json['result'])
    
    
def patch_package(id: str, package_metadata: dict):
    """
    This method utilizes the CKAN API to PATCH a package in the catalog.
    The package to be PATCHED must be defined with package metadata.
    Inside the package_metadata, resources cannot be defined or they will be omitted.

    Args:
    - id (str): The unique identifier for the dataset package that needs to be patched.
    - package_metadata (dict): A dictionary containing metadata to update the package (e.g., name, description, tags, etc.)
    
    Returns:
    - dict: The updated package information if successful.
    
    Raises:
    - ValueError: If the dataset with the given ID is not found.
    - Exception: For other types of exceptions during the request.
    """
    try:
        package_metadata["id"] = id
        if package_metadata.get("resources"):
            package_metadata.pop("resources")

        # Handle keywords appropriately
        if package_metadata.get('tags'):
            package_metadata['tags'] = utils.handle_keywords(package_metadata['tags'])

        response = request("POST","package","package_patch", json=package_metadata)
        if response.status_code == 200:
            return response.json().get('result')
        
    except requests.exceptions.HTTPError as he :
        if he.response.status_code == 404:
            raise ValueError(f"Dataset with ID: {id} was not found")
        else:
            raise Exception from he
    except Exception as e:
        raise Exception from e

def delete_package(id: str):
    try:
        if id:
            response = request("POST","package","dataset_purge",json={"id":id})
            if response.status_code == 200:
                return id
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Package with ID: {id} was not found")
        elif he.response.status_code == 409:
            raise AttributeError(f"Missing Parameters")
    except Exception as e:
        raise Exception from e

def get_package_resources(package_id: str, relation_filter: str = None):

    try:
        package = get_package(package_id)
        if relation_filter and relation_filter == 'owned':
            package['resources'] = [ resource for resource in package['resources'] if resource.get('relation', '') == 'owned' ] 
    
        return package['resources']

    except ValueError as ve:
        raise ValueError(f"Package with ID: {package_id} was not found")
    except Exception as e:
        raise Exception from e
    

def get_resource(id: str):
    try:
        if id:           
            response = request("GET","resource",'resource_show', params={"id":id})
            if response.status_code == 200:
                return response.json()['result']
        else:
            raise ValueError("ID cannot be empty")
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Resource with ID: {id} was not found")
    except Exception as e:
        raise Exception from e
    
 
def create_resource(package_id: str, resource_metadata: dict, relation_type: str = 'owned') -> dict:
    try:
        if package_id:
            resource_metadata['package_id'] = package_id
            resource_metadata['relation'] = relation_type           
           
            response = request("POST","resource",'resource_create', data=resource_metadata)

            if response.status_code == 200:
                resource_id = response.json()['result']['id']
                if resource_metadata.get("resource_type"):
                    sql_commands = utils.extractResourceProperties(resource_id, resource_metadata)
                    for sql in sql_commands:
                        utils.execSql(sql)

            return response.json()['result']
        
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Package with ID: {package_id} was not found")
    except Exception as e:
        raise Exception from e
            

def patch_resource(id:str, resource_metadata: dict):
    try:
        if id:           
            resource_metadata['id'] = id
            response = request("POST","resource",'resource_patch', data=resource_metadata)
            if response.status_code == 200:
                return response.json()['result']
        else:
            raise ValueError("ID cannot be empty")
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            raise ValueError(f"Resource with ID: {id} was not found")
        if he.response.status_code == 400:
            raise AttributeError(f"Missing parameters: {he}")
    except Exception as e:
        raise Exception from e
            

def delete_resource(id: str):
    try:
        if id:
            # Performing double delete because CKAN needs 2 resource delete requests to hard delete a resource.
            # Ugh....
            response = request("POST","resource","resource_delete",json={"id":id})
            if response.status_code == 200:
                response = request("POST","resource","resource_delete",json={"id":id})
            if response.status_code == 200:
                return id
        else:
            raise ValueError("ID cannot be empty")
    except requests.exceptions.HTTPError as he:
        raise ValueError(f"Resource with ID: {id} was not found")
    except Exception as e:
        raise Exception from e
    

##########################
# NOT IMPLEMENTED
##########################
def publish_profile(package_id: str, profile_metadata: dict ) -> dict:
    
    if profile_metadata.get('file'):

        with open(profile_metadata['file'], 'rb') as f:
            try:
                profile_metadata['package_id'] = package_id
                profile_metadata['relation'] = 'profile'

                # Use this instead of the custom create_resource method as we have a file
                response = request("POST", "resource","resource_create", data=profile_metadata, files=[('upload', f)])
                if response.status_code == 200:
                    prf = open(profile_metadata['file'])
                    profile = json.load(prf)
                    resource_id = response.json()['result']['id']

                    sql_commands = utils.extractProfileProperties(resource_id, profile)
                    for sql in sql_commands:
                        utils.execSql(sql)

                    return response.json()['result']
            except requests.exceptions.HTTPError as he:
                if he.response.status_code == 404:
                    raise ValueError(f"Package with ID: {package_id} was not found")
                elif he.response.status_code == 400:
                    raise AttributeError(f"Missing parameter fields for profile metadata: {he}")
            except Exception as e:
                raise Exception from e
        
    elif profile_metadata.get('url'):
        try:
            resource = create_resource(package_id, resource_metadata=profile_metadata, relation_type='profile')
            return resource
        except Exception as e:
            raise Exception from e