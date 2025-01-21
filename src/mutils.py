import hashlib
import io
import json
import logging
import subprocess
import xml.etree.ElementTree as ET

import requests
from flask import current_app, jsonify, make_response, render_template, request, session
from minio import Minio
from minio.commonconfig import CopySource
from minio.error import S3Error

logging.basicConfig(level=logging.DEBUG)


def initialize_minio_admin(ac_key, sec_key, token):
    config = current_app.config["settings"]
    minio_url = config["MINIO_API_SUBDOMAIN"] + "." + config["KLMS_DOMAIN_NAME"]
    client = Minio(
        minio_url,
        access_key=ac_key,
        secret_key=sec_key,
        session_token=token,
        secure=True,  # Set to False if you are using HTTP instead of HTTPS
    )
    return client


def get_temp_minio_credentials(access_token):
    """
    Get temporary MinIO credentials using the STS AssumeRoleWithWebIdentity.
    The response is in XML format, which we parse to retrieve credentials.
    """
    config = current_app.config["settings"]

    if access_token is None:
        try:
            raise ValueError("No access token found in call arguments.")
        except ValueError as e:
            # Handle the case where no token is found, return 401 Unauthorized
            return make_response(
                {
                    "success": False,
                    "error": {"__type": "Authorization Error", "name": [str(e)]},
                },
                401,
            )

    # Produce STS Token for MinIO Access
    minio_body = {
        "Action": "AssumeRoleWithWebIdentity",
        "WebIdentityToken": access_token,
        "Version": "2011-06-15",
        "DurationSeconds": "86000",
    }
    minio_url = config["MINIO_API_EXT_URL"]

    # Properly make a POST request to MinIO's STS endpoint
    response = requests.post(url=minio_url, params=minio_body)
    # Handle the response, parse XML if successful
    if response.status_code == 200:
        try:
            # Parse the XML response
            root = ET.fromstring(response.text)

            # Extracting relevant information from the XML
            credentials = root.find(
                ".//{https://sts.amazonaws.com/doc/2011-06-15/}Credentials"
            )
            if credentials is not None:
                access_key = (
                    credentials.find(
                        "{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId"
                    ).text
                    if credentials.find(
                        "{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId"
                    )
                    is not None
                    else None
                )
                secret_key = (
                    credentials.find(
                        "{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey"
                    ).text
                    if credentials.find(
                        "{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey"
                    )
                    is not None
                    else None
                )
                session_token = (
                    credentials.find(
                        "{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken"
                    ).text
                    if credentials.find(
                        "{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken"
                    )
                    is not None
                    else None
                )
                # Return credentials as a dictionary
                return {
                    "AccessKeyId": access_key,
                    "SecretAccessKey": secret_key,
                    "SessionToken": session_token,
                }
        except ET.ParseError as e:
            print("Failed to parse XML:", e)
    else:
        raise Exception("Credentials not found in the STS response")


def evaluate_write_access(credentials, bucket_name, object_name):
    """
    Checks if the user has write access to an object in MinIO by attempting to copy the object to itself.
    """
    # Initialize the MinIO client
    # config = current_app.config['settings']
    # minio_url = config['MINIO_API_SUBDOMAIN'] + "." + config['KLMS_DOMAIN_NAME']

    # client = Minio(
    #     minio_url,
    #     access_key=credentials['AccessKeyId'],
    #     secret_key=credentials['SecretAccessKey'],
    #     session_token=credentials['SessionToken'],
    #     secure=True  # Set to False if not using HTTPS
    # )

    client = initialize_minio_admin(
        ac_key=credentials["AccessKeyId"],
        sec_key=credentials["SecretAccessKey"],
        token=credentials["SessionToken"],
    )

    # Create a copy source object
    copy_source = CopySource(bucket_name, object_name)

    try:
        # Attempt to copy the object to the same path, while updating the metadata
        client.copy_object(
            bucket_name=bucket_name,
            object_name=object_name,
            source=copy_source,
            metadata={"x-amz-meta-write-access-test": "true"},  # Add custom metadata
            metadata_directive="REPLACE",  # Ensure the metadata is replaced to make the copy valid
        )
        logging.debug(
            f"Copy operation succeeded. Write access is allowed for {bucket_name}/{object_name}."
        )
        return True  # The copy succeeded, meaning write access exists
    except S3Error as err:
        if err.code == "AccessDenied":
            logging.debug(
                f"Access denied. Write access is not allowed for {bucket_name}/{object_name}."
            )
        else:
            logging.debug(f"Error during copy operation: {err}")
        return False  # Copy failed, meaning no write access


def list_buckets_with_folders(credentials):
    # Initialize the MinIO client with STS credentials

    # config = current_app.config['settings']

    # minio_url = config['MINIO_API_SUBDOMAIN'] + "." + config['KLMS_DOMAIN_NAME']

    # client = Minio(
    #     minio_url,
    #     access_key=credentials['AccessKeyId'],
    #     secret_key=credentials['SecretAccessKey'],
    #     session_token=credentials['SessionToken'],
    #     secure=True  # Set to False if you are using HTTP instead of HTTPS
    # )

    client = initialize_minio_admin(
        ac_key=credentials["AccessKeyId"],
        sec_key=credentials["SecretAccessKey"],
        token=credentials["SessionToken"],
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
            seen = {}
            # Here we should use TRY to list the objects of the bucket to avoid exceptions
            # happening if the user has no access to bucket due to policy.
            try:
                objects = client.list_objects(bucket_name, recursive=True)
                for obj in objects:
                    obj_name = obj.object_name
                    # Split the input string by '/'
                    parts = obj_name.split("/")
                    # Initialize an empty list to store the paths
                    paths = []
                    # Build the paths incrementally
                    current_path = ""
                    for part in parts[:-1]:  # Exclude the last part (the filename)
                        current_path = current_path + part + "/"
                        if current_path not in seen:
                            paths.append(current_path)

                    for path in paths:
                        if "/" in path:
                            empty_content = io.BytesIO(b"")
                            try:
                                client.put_object(
                                    bucket_name, path, data=empty_content, length=0
                                )
                            except S3Error:
                                continue
                            if evaluate_write_access(credentials, bucket_name, path):
                                folders.add(path)
                            seen[path] = True
            except Exception as e:
                continue
            # Store the folders in the result dictionary
            result[bucket_name] = list(folders)

        # Return the result as a JSON string
        return result

    except S3Error as exc:
        print(f"Error occurred: {exc}")
        # logging.debug(exc)
        return None


def create_bucket_and_subfolders(minio_client, bucket_info):
    bucket_name = bucket_info["bucketname"]

    # Create the bucket if it does not exist
    if not minio_client.bucket_exists(bucket_name):
        minio_client.make_bucket(bucket_name)
        print(f"Bucket '{bucket_name}' created successfully.")
    else:
        print(f"Bucket '{bucket_name}' already exists.")

    # Recursively create subfolders
    def create_subfolders(bucket_name, subfolders, parent_path=""):
        for subfolder in subfolders:
            subfolder_path = f"{parent_path}{subfolder['name']}/"
            # Create the "subfolder" by uploading an empty object with the subfolder path
            empty_content = io.BytesIO(b"")
            minio_client.put_object(bucket_name, subfolder_path, empty_content, 0)
            print(
                f"Subfolder '{subfolder_path}' created successfully in bucket '{bucket_name}'."
            )
            # Recursively create sub-subfolders
            if "subfolders" in subfolder:
                create_subfolders(bucket_name, subfolder["subfolders"], subfolder_path)

    if "subfolders" in bucket_info:
        create_subfolders(bucket_name, bucket_info["subfolders"])


def generate_random_hash(policy_json) -> str:
    # Generate 32 random bytes
    # random_bytes = os.urandom(32)

    # Create a SHA-256 hash object
    policy_hash = hashlib.sha256(policy_json.encode("utf-8")).hexdigest()

    # Get the hexadecimal representation of the hash

    return policy_hash


def create_policy(perm_info):
    policy_names_list = []

    for perm in perm_info:
        if perm["action"] == "read,write":  # na to do
            action = ["s3:GetObject", "s3:PutObject"]
        elif perm["action"] == "read":
            action = ["s3:GetObject"]
        elif perm["action"] == "write":
            action = ["s3:PutObject"]

        resource_part = perm["resource"].split("/", 1)
        if len(resource_part[1].replace("*", "")) > 1:
            resource_sub_part = resource_part[1]
            policy_document = [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
                    "Resource": ["arn:aws:s3:::*"],
                    # "Condition": {"StringLike": {"s3:prefix": [f"{perm['resource']}"]}}
                },
                # {
                #     "Effect": "Allow",
                #     "Action": ["s3:ListBucket"],
                #     "Resource": ["arn:aws:s3:::" + perm['resource'].split('/')[0]],
                #     "Condition": {"StringEquals": {"s3:prefix": ["",f"{perm['resource'].replace('*','').split('/')[1]}/"],"s3:delimiter":["/"]}}
                # },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::" + perm["resource"].split("/")[0]],
                    "Condition": {
                        "StringLike": {"s3:prefix": [f"{resource_sub_part}"]}
                    },
                },
                {
                    "Effect": "Allow",
                    "Action": action,
                    "Resource": ["arn:aws:s3:::" + perm["resource"]],
                },
            ]
        else:
            policy_document = [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
                    "Resource": ["arn:aws:s3:::*"],
                    # "Condition": {"StringLike": {"s3:prefix": [f"{perm['resource']}"]}}
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::" + perm["resource"].split("/")[0]],
                },
                {
                    "Effect": "Allow",
                    "Action": action,
                    "Resource": ["arn:aws:s3:::" + perm["resource"]],
                },
            ]

        # Define the policy
        policy = {"Version": "2012-10-17", "Statement": policy_document}

        # Convert the policy dictionary to a JSON string

        policy_json = json.dumps(policy)

        hashed_policy_name = generate_random_hash(policy_json)

        policy_file = f"{hashed_policy_name}.json"
        with open(policy_file, "w") as file:
            file.write(policy_json)

        try:
            # Create the policy using mc client
            subprocess.run(
                [
                    "mc",
                    "admin",
                    "policy",
                    "create",
                    "myminio",
                    hashed_policy_name,
                    policy_file,
                ],
                check=True,
            )
            print(f"Policy '{hashed_policy_name}' created successfully.")

            # Apply the policy to the user
        except subprocess.CalledProcessError as err:
            print(f"Error occurred: {err}")

        policy_names_list.append(hashed_policy_name)

    return policy_names_list


def delete_policies(policies_to_delete):
    for policy in policies_to_delete:
        # delete_command = "mc admin policy rm myminio " + policy
        subprocess.run(["mc", "admin", "policy", "rm", "myminio", policy])
