#
# Central pytest configuration
# -----------------------------
#
# This is the location for declaring fixtures and other utilities that are auto-included
# in test files.
from __future__ import annotations

import socket
import subprocess
import time
from collections import namedtuple
from contextlib import closing
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


@pytest.fixture(scope="session")
def pg_access():
    c = cc.testcluster_config()
    context = c["cluster"]["context"]
    local_port = c["cluster"]["postgres"]["local_port"]

    if context is not None:
        ctxopt = ["--context", context]
    else:
        ctxopt = []

    # Test the local port for availability
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex(("localhost", local_port)) == 0:
            # Port is already in use, assume that a port-forward is already running
            CONNECT = False
        else:
            # Port is not in use, start a port-forward
            CONNECT = True

    if CONNECT:
        proc = subprocess.Popen(
            ["kubectl", *ctxopt, "port-forward", "svc/db", f"{local_port}:5432"],
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
def monkeysession(request):
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture(scope="session")
def app(monkeysession, pg_access):
    c = cc.testcluster_config()
    cm = cc.stelar_api_cm()

    scheme = c["cluster"]["net"]["scheme"]
    dn = c["cluster"]["net"]["dn"]

    ckan_url = f"{scheme}://klms.{dn}/dc"
    kc_url = f"{scheme}://kc.{dn}/"
    kc_ext_url = f"{scheme}://kc.{dn}/"

    monkeysession.setenv("POSTGRES_HOST", "localhost")
    monkeysession.setenv("POSTGRES_PORT", str(c["cluster"]["postgres"]["local_port"]))
    monkeysession.setenv("POSTGRES_USER", cm["POSTGRES_USER"])
    monkeysession.setenv("POSTGRES_PASSWORD", cc.postgres_password())
    monkeysession.setenv("POSTGRES_DB", cm["POSTGRES_DB"])

    monkeysession.setenv("CKAN_SITE_URL", ckan_url)
    monkeysession.setenv("CKAN_ADMIN_TOKEN", cc.ckan_api_token())

    monkeysession.setenv("KEYCLOAK_URL", kc_url)
    monkeysession.setenv("KEYCLOAK_EXT_URL", kc_url)
    monkeysession.setenv("KEYCLOAK_ISSUER_URL", f"{kc_url}realms/master")
    monkeysession.setenv("KEYCLOAK_CLIENT_SECRET", cc.kc_client_secret())

    monkeysession.setenv("REALM_NAME", cm["REALM_NAME"])

    # Disable execution engine. This is a test environment
    # and it is not possible for a in-cluster job to contact us for
    # its parameters etc.
    # TODO: figure out how to test the execution engine
    monkeysession.setenv("EXECUTION_ENGINE", "none")

    app = create_app()
    app.config.update({"TESTING": True})

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
