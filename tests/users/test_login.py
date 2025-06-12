import cluster_config as cc
import pytest

import kutils


@pytest.mark.skip()
def test_get_token(app):
    with app.app_context():
        tok = kutils.get_token("johndoe", "johndoe")
        assert tok is not None


@pytest.fixture()
def testuser(dev_cluster_config):
    cluster = dev_cluster_config["cluster"]
    client_context = cluster["access"]["client_context"]
    client_config = cluster["access"].get("client_config", None)

    # load the client context from ~/.stelar
    username, password = cc.client_context(client_context, client_config)

    return username, password


def test_api_users_token_johndoe(testcli):
    response = testcli.POST(
        "v1/users/token", username="johndoe", password="johndoe_secret"
    )
    assert response.status_code == 200
    assert response.json()["success"] == True

    token_json = response.json()["result"]

    assert token_json["token_type"] == "Bearer"
    assert "token" in token_json
    assert "expires_in" in token_json
    assert "refresh_token" in token_json
    assert "refresh_expires_in" in token_json


def test_api_users_token_testuser(testcli, testuser):
    username, password = testuser
    response = testcli.POST("v1/users/token", username=username, password=password)
    assert response.status_code == 200
    assert response.json()["success"] == True
    assert "token" in response.json()["result"]
