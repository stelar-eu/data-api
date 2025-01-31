"""
This file contains code that processes the pytest_cluster_config.yaml
file.
"""
import subprocess


def testcluster_config():
    """Return the parsed file"""
    import yaml

    with open("pytest_cluster_config.yaml") as f:
        return yaml.safe_load(f)


def testclusters_by_engine(engine: str) -> list:
    """Return all testcluster configurations with kubernetes engines"""
    return [
        cluster
        for cluster in testcluster_config().values()
        if cluster["execution"]["engine"] == "kubernetes"
    ]


def k8s_secret(context, secret, var):
    cmd = f"kubectl {context} get secrets {secret} -o json|jq .data.{var} -r|base64 -d"

    return subprocess.check_output(cmd, shell=True, text=True)


def ckan_api_token(context=None):
    ctx = f"--context {context}" if context else ""
    secret = "ckan-admin-token-secret"
    var = "token"
    return k8s_secret(ctx, secret, "token")
