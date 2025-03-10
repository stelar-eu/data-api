#
# Central pytest configuration
# -----------------------------
#
# This is the location for declaring fixtures and other utilities that are auto-included
# in test files.
from __future__ import annotations

import json
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


# In this function we put code executed before almost everything else
def pytest_configure(config):
    # Fix a bug in FlaskClient.
    import werkzeug

    werkzeug.__version__ = "3.1.3"


@pytest.fixture(scope="session")
def kconfig():
    """Run load_kube_config() to initialize kubernetes API.

    After this is run, tests can use the kubernetes API to interact with the
    default cluster.

    FIXME: this does not load the pytest_cluster_config.yaml file, it just
    loads the default context in ~/.kube/config.
    """

    from kubernetes import client, config

    config.load_kube_config()
    return client.Configuration.get_default_copy()


@pytest.fixture(scope="session")
def dev_cluster_config(scope="session"):
    """Return the pytest_cluster_config.yaml file as an object."""
    return cc.testcluster_config()


@pytest.fixture(scope="session")
def pg_access():
    """Start a port-forward to the testcluster's PostgreSQL database.

    This fixture starts a kubectl port-forward to the testcluster's PostgreSQL.
    This allows tests and the data_app code to connect to the database.
    """

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
    """A session-scoped monkeypatch context.

    This is straight out of the pytest documentation.
    """
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture(scope="session")
def app(monkeysession, pg_access):
    """Create a test app with the testcluster configuration.

    The app is configured to use the testcluster's PostgreSQL database and
    CKAN API, as well as the keycloak server.
    """

    c = cc.testcluster_config()
    k8s_context = c["cluster"]["context"]

    # Get the stelar api config map from kubernetes
    cm = cc.stelar_api_cm(k8s_context)

    scheme = c["cluster"]["net"]["scheme"]
    dn = c["cluster"]["net"]["dn"]

    ckan_url = f"{scheme}://klms.{dn}/dc"
    kc_url = f"{scheme}://kc.{dn}/"
    kc_ext_url = f"{scheme}://kc.{dn}/"

    monkeysession.setenv("POSTGRES_HOST", "localhost")
    monkeysession.setenv("POSTGRES_PORT", str(c["cluster"]["postgres"]["local_port"]))
    monkeysession.setenv("POSTGRES_USER", cm["POSTGRES_USER"])
    monkeysession.setenv("POSTGRES_PASSWORD", cc.postgres_password(k8s_context))
    monkeysession.setenv("POSTGRES_DB", cm["POSTGRES_DB"])

    monkeysession.setenv("CKAN_SITE_URL", ckan_url)
    monkeysession.setenv("CKAN_ADMIN_TOKEN", cc.ckan_api_token())

    monkeysession.setenv("KEYCLOAK_URL", kc_url)
    monkeysession.setenv("KEYCLOAK_EXT_URL", kc_ext_url)
    monkeysession.setenv("KEYCLOAK_ISSUER_URL", f"{kc_url}realms/master")
    monkeysession.setenv("KEYCLOAK_CLIENT_SECRET", cc.kc_client_secret(k8s_context))
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
    """Return a test client for the app."""
    return app.test_client()


@pytest.fixture()
def runner(app):
    """Return a test runner for the app."""
    return app.test_cli_runner()


@pytest.fixture()
def app_context(app):
    """Return an app context for the app."""
    with app.app_context():
        yield


Credentials = namedtuple("Credentials", ["token", "refresh_token"])


@pytest.fixture(scope="module")
def credentials(app: APIFlask) -> Generator[Credentials]:
    """Return a set of credentials for the testcluster.

    This set is obtained from the keycloak server using
    """
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


@pytest.fixture
def app_client(app, credentials):
    with app.test_client() as client:
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {credentials.token}"
        yield client


@pytest.fixture(scope="session")
def DC():
    """A CKAN api object (DC == Data Catalog). Call on it the ckan api methods.

    E.g.:
    ```
    pkg = DC.package_show(id='shakespeare_novels')
    org = DC.organization_show(id='stelar-klms')
    p = DC.package_create(name='just_a_test', title='Just a test', owner_org='stelar-klms')
    DC.dataset_purge(id=p['id'])
    ```
    """
    from cluster_config import testcluster_ckan_api

    return testcluster_ckan_api()


@pytest.fixture(scope="session")
def mdb_dsn():
    """Return the DSN for the testcluster's PostgreSQL database.

    This can be used to connect to the metadata database using a PostgreSQL
    client. For example:

    ```
    def test_pg_connection(pg_dsn):
        import psycopg2

        conn = psycopg2.connect(pg_dsn)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        assert cur.fetchone() == (1,)
    ```
    """
    return cc.testcluster_pg_dsn()


@pytest.fixture
def mdb_conn(mdb_dsn):
    """Return a connection to the metadata database."""
    import psycopg2

    conn = psycopg2.connect(mdb_dsn)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def ckan_solr_schema_cached():
    """Return the CKAN Solr schema as a json object."""
    with open("tests/data/ckan_solr_schema.json") as f:
        rsp = json.load(f)
        return rsp["result"]["schema"]
