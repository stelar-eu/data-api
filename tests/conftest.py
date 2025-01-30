#
# Central pytest configuration
# -----------------------------
#
# This is the location for declaring fixtures and other utilities that are auto-included
# in test files.
import cluster_config as cc
import pytest

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


@pytest.fixture()
def app():
    app = create_app()
    app.config.update({"TESTING": True})
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
