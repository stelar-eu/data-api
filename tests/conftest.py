#
# Central pytest configuration
# -----------------------------
#
# This is the location for declaring fixtures and other utilities that are auto-included
# in test files.
import subprocess
import time

import cluster_config as cc
import pytest
import werkzeug

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
def kubectl_port_forward():
    c = cc.testcluster_config()

    context = c["cluster"]["context"]

    if context is not None:
        ctxopt = ["--context", context]
    else:
        ctxopt = []

    proc = subprocess.Popen(
        ["kubectl", *ctxopt, "port-forward", "svc/ckan", "5000:5000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Give kubectl some time to establish the port-forward
    time.sleep(5)

    yield

    # Terminate the kubectl process after tests are done
    proc.terminate()
    proc.wait()


@pytest.fixture(scope="session")
def app(kubectl_port_forward):
    c = cc.testcluster_config()
    scheme = c["cluster"]["net"]["scheme"]
    dn = c["cluster"]["net"]["dn"]

    # ckan_url = f"{scheme}://klms.{dn}/dc"
    ckan_url = f"{scheme}://localhost:5000/"

    app = create_app()
    app.config.update({"TESTING": True, "CKAN_SITE_URL": ckan_url})

    config = app.config["settings"]
    config["CKAN_API"] = f"{ckan_url}/api/3/action/"
    config["CKAN_ADMIN_TOKEN"] = cc.ckan_api_token()

    config["KEYCLOAK_URL"] = f"{scheme}://kc.{dn}/"
    config["KEYCLOAK_EXT_URL"] = f"{scheme}://kc.{dn}/"
    config["KEYCLOAK_ISSUER_URL"] = f"{scheme}://kc.{dn}/realms/master"
    config["KEYCLOAK_CLIENT_SECRET"] = ""

    # Yield the configured app
    yield app


@pytest.fixture()
def client(app) -> werkzeug.Client:
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


@pytest.fixture()
def credentials(client: werkzeug.Client):
    match cc.testcluster_config():
        case {"cluster": {"access": access}}:
            pass
        case _:
            assert False

    match client.post("/api/v1/users/token", json=access):
        case {"success": True, "result": result}:
            return result
        case _:
            assert False

    return None
