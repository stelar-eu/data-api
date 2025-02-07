import cluster_config as cc
import pytest

import kutils


def test_get_token(app):
    with app.app_context():
        tok = kutils.get_token("johndoe", "johndoe2")
        assert tok is not None


@pytest.fixture()
def testuser(dev_cluster_config):
    cluster = dev_cluster_config["cluster"]
    client_context = cluster["access"]["client_context"]
    client_config = cluster["access"].get("client_config", None)

    # load the client context from ~/.stelar
    username, password = cc.client_context(client_context, client_config)

    return username, password


def test_get_testuser_token(app, testuser):
    # load the client context from ~/.stelar
    username, password = testuser

    with app.app_context():
        tok = kutils.get_token(username, password)
        assert tok is not None


def test_api_users_token_johndoe(client):
    response = client.post(
        "/api/v1/users/token", json={"username": "johndoe", "password": "johndoe2"}
    )
    assert response.status_code == 200
    assert response.json["success"] == True
    assert "token" in response.json["result"]
    # assert "expires" in response.json["result"]
    # assert "user" in response.json["result"]
    # assert response.json["result"]["user"] == "johndoe"


def test_api_users_token_testuser(client, testuser):
    username, password = testuser
    response = client.post(
        "/api/v1/users/token", json={"username": username, "password": password}
    )
    assert response.status_code == 200
    assert response.json["success"] == True
    assert "token" in response.json["result"]
