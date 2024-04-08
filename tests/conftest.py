# 
# Central pytest configuration
# -----------------------------
#
# This is the location for declaring fixtures and other utilities that are auto-included
# in test files.
import pytest
import cluster_config as cc

@pytest.fixture(scope='session')
def kconfig():
    from kubernetes import config, client
    config.load_kube_config()
    return client.Configuration.get_default_copy()

@pytest.fixture(scope='session')
def dev_cluster_config(scope='session'):
    return cc.testcluster_config()

@pytest.fixture(params=cc.testclusters_by_engine('kubernetes'))
def testcluster_kubernetes(kconfig, request):
    return request.param
