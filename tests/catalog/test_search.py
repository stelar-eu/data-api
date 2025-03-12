import jmespath


def test_entity_search(app_client):
    response = app_client.post(
        "/api/v2/search/datasets",
        json={
            "q": "package",
            "fl": ["name"],
            "sort": "name desc",
            "facet": {"fields": ["tags"], "mincount": 1, "limit": 10},
            "limit": 10,
            "offset": 0,
        },
    )

    assert response.status_code == 200

    result = response.get_json()["result"]
    assert result["count"] >= 0
    assert len(result["results"]) <= result["count"]
    assert all(
        a in result for a in ["count", "results", "facets", "sort", "search_facets"]
    )
    assert all("name" in r for r in result["results"])


def dosearch(cli, endp, filter=None, **query):
    response = cli.post(f"/api/v2/search/{endp}", json=query)
    assert response.status_code == 200
    if filter is None:
        return response.get_json()["result"]
    else:
        return jmespath.search(filter, response.get_json()["result"])


def test_search_list_datasets(app_client):
    response = app_client.post(
        "/api/v2/search/datasets", json=dict(q="*.*", fl=["id", "type"])
    )

    assert response.status_code == 200

    result = response.get_json()["result"]
    count = result["count"]
    assert count >= 0

    # Check that the number of results is less than or equal to the total count
    assert len(result["results"]) <= count
    assert all(d["type"] == "dataset" for d in result["results"])

    # Get a list of a few dataset IDs
    dataset_ids = dosearch(
        app_client, "datasets", filter="results[*].id", q="*.*", limit=4
    )
    assert len(dataset_ids) == min(count, 4)


def test_search_resources(app_client):
    response = app_client.post(
        "/api/v2/search/resources", json=dict(query=["format:TXT"])
    )

    assert response.status_code == 200
    result = response.get_json()["result"]
    count = result["count"]
    assert count >= 0

    # Check that the number of results is less than or equal to the total count
    assert len(result["results"]) <= count

    # Get a list of a few resource IDs
    resource_ids = dosearch(
        app_client, "resources", filter="results[*].id", query=[], limit=4
    )
    assert len(resource_ids) == min(count, 4)
