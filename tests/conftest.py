#
# Central pytest configuration
# -----------------------------
#
# This is the location for declaring fixtures and other utilities that are auto-included
# in test files.
from __future__ import annotations

import subprocess
import time
from collections import namedtuple
from typing import Generator

import cluster_config as cc
import pytest
import werkzeug
from apiflask import APIFlask
from keycloak import KeycloakOpenID

from data_api import create_app


@pytest.fixture(scope="session")
def kconfig():
    from kubernetes import client, config

    config.load_kube_config()
    return client.Configuration.get_default_copy()


@pytest.fixture(scope="session")
def dev_cluster_config(scope="session"):
    return cc.testcluster_config()


@pytest.fixture(params=cc.testclusters_by_engine("kubernetes"))
def testcluster_kubernetes(kconfig, request):
    return request.param


CONNECT = False


@pytest.fixture(scope="session")
def kubectl_port_forward():
    c = cc.testcluster_config()

    context = c["cluster"]["context"]

    if context is not None:
        ctxopt = ["--context", context]
    else:
        ctxopt = []

    if CONNECT:
        proc = subprocess.Popen(
            ["kubectl", *ctxopt, "port-forward", "svc/ckan", "5000:5000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Give kubectl some time to establish the port-forward
        time.sleep(5)

    yield

    if CONNECT:
        # Terminate the kubectl process after tests are done
        proc.terminate()
        proc.wait()


@pytest.fixture(scope="session")
def app(kubectl_port_forward):
    c = cc.testcluster_config()
    scheme = c["cluster"]["net"]["scheme"]
    dn = c["cluster"]["net"]["dn"]

    if CONNECT:
        ckan_url = f"{scheme}://localhost:5000/"
    else:
        ckan_url = f"{scheme}://klms.{dn}/dc"
        kc_url = f"{scheme}://kc.{dn}/"
    kc_ext_url = f"{scheme}://kc.{dn}/"

    app = create_app()
    app.config.update({"TESTING": True, "CKAN_SITE_URL": ckan_url})

    config = app.config["settings"]
    config["CKAN_API"] = f"{ckan_url}/api/3/action/"
    config["CKAN_ADMIN_TOKEN"] = cc.ckan_api_token()

    config["KEYCLOAK_URL"] = kc_url
    config["KEYCLOAK_EXT_URL"] = kc_url
    config["KEYCLOAK_ISSUER_URL"] = f"{kc_url}realms/master"
    config["KEYCLOAK_CLIENT_SECRET"] = cc.kc_client_secret()

    # Yield the configured app
    yield app


@pytest.fixture()
def client(app) -> werkzeug.Client:
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


Credentials = namedtuple("Credentials", ["token", "refresh_token"])


@pytest.fixture(scope="module")
def credentials(app: APIFlask) -> Generator[Credentials]:
    config = app.config["settings"]
    cli = KeycloakOpenID(
        server_url=config["KEYCLOAK_URL"],
        client_id=config["KEYCLOAK_CLIENT_ID"],
        realm_name=config["REALM_NAME"],
        client_secret_key=config["KEYCLOAK_CLIENT_SECRET"],
        verify=True,
    )

    match cc.testcluster_config():
        case {"cluster": {"access": {"username": username, "password": password}}}:
            pass
        case {
            "cluster": {
                "access": {"client_context": cprofile, "client_config": cfgfile}
            }
        }:
            username, password = cc.client_context(cprofile, cfgfile)
        case {"cluster": {"access": {"client_context": cprofile}}}:
            username, password = cc.client_context(cprofile)
        case _:
            assert False

    cred = cli.token(username=username, password=password)
    yield Credentials(cred["access_token"], cred["refresh_token"])

    cli.logout(refresh_token=cred["refresh_token"])
