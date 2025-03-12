from keycloak import KeycloakAdmin
from minio import MinioAdmin
from minio.credentials.providers import MinioClientConfigProvider,StaticProvider
import pytest
from apiflask import APIFlask
import cluster_config as cc
from data_api import create_app
from mutils import generate_random_hash
import json
import os


@pytest.fixture(scope="module")
def keycloak_admin():
    c = cc.testcluster_config()

    scheme = c["cluster"]["net"]["scheme"]
    dn = c["cluster"]["net"]["dn"]
    kc_url = f"{scheme}://kc.{dn}/"
    cprofile = c["cluster"]["access"]["client_context"]
    usr,passwd = cc.client_context(cprofile)
    return KeycloakAdmin(server_url=kc_url, username=usr, password=passwd, realm_name="master", verify=True)

@pytest.fixture(scope="module")
def minio_admin():
    c = cc.testcluster_config()
    scheme = c["cluster"]["net"]["scheme"]
    dn = c["cluster"]["net"]["dn"]
    mc_url = f"minio.{dn}"
    cprofile = c["cluster"]["access"]["client_context"]
    usr,passwd = cc.client_context(cprofile)
    return MinioAdmin(mc_url, credentials=StaticProvider(access_key="root",secret_key=passwd),secure=False, cert_check=False)


def fake_minio_create_policy(minio_admin,perm):
    
    policy_names_list = []

    # for perm in perm_info:
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
            },
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

    minio_admin.policy_add(hashed_policy_name, policy_file)

    os.remove(policy_file)

    policy_names_list.append(hashed_policy_name)

    return policy_names_list