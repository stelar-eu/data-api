"""
This file contains code that processes the pytest_cluster_config.yaml
file.
"""

import pytest


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
        if cluster['execution']['engine'] == 'kubernetes'
    ]
