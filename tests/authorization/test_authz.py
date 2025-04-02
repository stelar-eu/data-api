from typing import Generator

import pytest
from apiflask import APIFlask
from keycloak import KeycloakOpenID


def user_credentials(cli: KeycloakOpenID, username: str, password: str):
    """Return a set of credentials for the testcluster.

    This set is obtained from the keycloak server using
    """

    cred = cli.token(username=username, password=password)
    return (cred["access_token"], cred["refresh_token"])

    # cli.logout(refresh_token=cred["refresh_token"])


@pytest.fixture(scope="module")
def johndoe_client(app, keycloak_client):
    acc, rfr = user_credentials(keycloak_client, "johndoe", "johndoe")
    try:
        with app.test_client() as client:
            client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {acc}"
            yield client

    finally:
        keycloak_client.logout(refresh_token=rfr)


def test_johndoe(johndoe_client):
    init_data = {
        "name": "going-to-fail",
        "owner_org": "stelar-klms",
    }

    resp = johndoe_client.post("/api/v2/dataset", json=init_data)

    assert resp.status_code == 403
    json = resp.get_json()
    assert json["success"] is False
    assert json["error"]["detail"]["action"] == "create_dataset"

    resp = johndoe_client.get("/api/v2/dataset/test-dummy1")
    json = resp.get_json()
    print(json)
    assert resp.status_code == 200
    assert json["result"]["name"] == "test-dummy1"

    resp = johndoe_client.get("/api/v2/dataset/package4")
    json = resp.get_json()
    assert resp.status_code == 403
    assert json["error"]["detail"]["action"] == "read_dataset"
