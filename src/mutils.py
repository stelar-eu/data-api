
from flask import request, jsonify, current_app, session, make_response, render_template
from minio import Minio
from minio.error import S3Error
import requests
import xml.etree.ElementTree as ET
import logging


logging.basicConfig(level=logging.DEBUG)


def get_temp_minio_credentials(access_token):
    """
    Get temporary MinIO credentials using the STS AssumeRoleWithWebIdentity.
    The response is in XML format, which we parse to retrieve credentials.
    """
    config = current_app.config['settings']

    if access_token is None:
        try:
            raise ValueError("No access token found in call arguments.")
        except ValueError as e:
        # Handle the case where no token is found, return 401 Unauthorized
            return make_response({
                'success': False, 
                'error': {
                    '__type': 'Authorization Error',
                    'name': [str(e)]
                }
            }, 401)
    
    # Produce STS Token for MinIO Access 
    minio_body = {      
        'Action':'AssumeRoleWithWebIdentity',
        'WebIdentityToken': access_token, 
        'Version' : '2011-06-15',
        'DurationSeconds' : '86000'
    }
    minio_url = "https://"+config['MINIO_API_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']

    # Properly make a POST request to MinIO's STS endpoint
    response = requests.post(
        url=minio_url, 
        params=minio_body
    )
        # Handle the response, parse XML if successful
    if response.status_code == 200:
        try:
            # Parse the XML response
            root = ET.fromstring(response.text)
            
            # Extracting relevant information from the XML
            credentials = root.find('.//{https://sts.amazonaws.com/doc/2011-06-15/}Credentials')
            if credentials is not None:
                access_key = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId') is not None else None
                secret_key = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey') is not None else None
                session_token = credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken').text if credentials.find('{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken') is not None else None
                  # Return credentials as a dictionary
                return {
                    'AccessKeyId': access_key,
                    'SecretAccessKey': secret_key,
                    'SessionToken': session_token
                }
        except ET.ParseError as e:
            print("Failed to parse XML:", e)
    else:
        raise Exception("Credentials not found in the STS response")



def evaluate_object_access(credentials, bucket, object_path):
    config = current_app.config['settings']

    minio_url = config['MINIO_API_SUBDOMAIN'] + "." + config['KLMS_DOMAIN_NAME']

    client = Minio(
        minio_url,
        access_key=credentials['AccessKeyId'],
        secret_key=credentials['SecretAccessKey'],
        session_token=credentials['SessionToken'],
        secure=True  # Set to False if you are using HTTP instead of HTTPS
    )

    try:
        client.stat_object(bucket, object_path)
        return True
    except S3Error as e:
        if e.code == 'AccessDenied':
            return False
        return False


   
def list_buckets_with_folders(credentials):
    # Initialize the MinIO client with STS credentials

    config = current_app.config['settings']

    minio_url = config['MINIO_API_SUBDOMAIN'] + "." + config['KLMS_DOMAIN_NAME']

    client = Minio(
        minio_url,
        access_key=credentials['AccessKeyId'],
        secret_key=credentials['SecretAccessKey'],
        session_token=credentials['SessionToken'],
        secure=True  # Set to False if you are using HTTP instead of HTTPS
    )

    try:
        # List all buckets
        buckets = client.list_buckets()
        result = {}

        # Loop through each bucket to list "folders" (prefixes)
        for bucket in buckets:
            bucket_name = bucket.name
            # Use list_objects with recursive=False to only get "folders"
            folders = set()
            # Here we should use TRY to list the objects of the bucket to avoid exceptions
            # happening if the user has no access to bucket due to policy.
            try:
                objects = client.list_objects(bucket_name, recursive=True)
                for obj in objects:
                    # If the object name ends with '/', it is a folder
                    if obj.object_name.endswith('/'):
                        folders.add(obj.object_name)
            except:
                continue
            # Store the folders in the result dictionary
            result[bucket_name] = list(folders)

        # Return the result as a JSON string
        return result
    
    except S3Error as exc:
        print(f"Error occurred: {exc}")
        #logging.debug(exc)
        return None
