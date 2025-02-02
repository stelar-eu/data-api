"""
This file contains code that processes the pytest_cluster_config.yaml
file.
"""
from __future__ import annotations

import json
import subprocess
from configparser import ConfigParser
from pathlib import Path
from typing import TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from os import PathLike


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


def k8s_secret(context: str, secret: str, var: str) -> str:
    """Return the 'secret data' stored in an opaque kubernetes secret.

    Access to the kubernetes cluster is done via the keycloak command,
    which must be on the path.

    The data is decoded and returned ready to use.

    In the following example:
    ``
    % kubectl describe secret ckan-admin-token-secret
    Name:         ckan-admin-token-secret
    Namespace:    stelar-notls
    Labels:       <none>
    Annotations:  <none>

    Type:  Opaque

    Data
    ====
    token:  175 bytes
    ``

    this function would be called as
    ```Python
    k8s_secret(None, "ckan-admin-token-secret", 'token')
    ```

    Arguments:
        context: The kubectl context to use. The context must already
            be configured with the correct namespace for the STELAR installation.
            Note: this can be done via 'kubectl config ...' commands.
        secret: The name of the kubernetes secret.
        var: The field name inside the "data:" field.

    Returns:
        The 'secret data'
    """
    ctx = f"--context {context}" if context else ""
    cmd = f"kubectl {ctx} get secrets {secret} -o json|jq .data.{var} -r|base64 -d"

    return subprocess.check_output(cmd, shell=True, text=True)


def stelar_api_cm(context=None):
    """Return the 'api-config-map' settings from the eponymous kubernetes config map."""
    ctx = f"--context {context}" if context else ""
    cmd = f"kubectl {ctx} get cm api-config-map -o json|jq .data"

    jsdict = subprocess.check_output(cmd, shell=True, text=True)
    return json.loads(jsdict)


def ckan_api_token(context=None):
    secret = "ckan-admin-token-secret"
    return k8s_secret(context, secret, "token")


def kc_client_secret(context=None):
    secret = "stelar-api-client-secret"
    return k8s_secret(context, secret, "secret")


def postgres_password(context=None):
    return k8s_secret(context, "ckandb-secret", "password")


def client_context(context: str, cfgfile: PathLike = None) -> Tuple[str, str]:
    config_file = cfgfile if cfgfile else Path.home() / ".stelar"
    c = ConfigParser()
    c.read(config_file)
    if not c.has_section(context):
        raise ValueError(f"Client context '{context}' does not exist")
    ctx = c[context]
    usr = ctx["username"]
    pwd = ctx["password"]
    return usr, pwd
