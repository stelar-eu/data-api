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
