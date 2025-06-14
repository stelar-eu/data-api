import jmespath
import pytest

from backend.ckan import ckan_request, get_id_for_entity_id_or_name


@pytest.mark.skip()
def test_id_from_entity_id_or_name(app_context):
    """Test the get_id_for_entity_id_or_name function."""
    # Test with a valid entity ID
    entity_id = "12345"
    result = get_id_for_entity_id_or_name(entity_id)
    assert result is None

    # Test with a list of packages
    result = ckan_request("current_package_list_with_resources")
    pairs = jmespath.search("[].[id, name]", result)

    for id, name in pairs:
        assert get_id_for_entity_id_or_name(name) == id
        assert get_id_for_entity_id_or_name(id) == id

    # Test with an invalid name
    assert get_id_for_entity_id_or_name("invalid!name") is None
    assert get_id_for_entity_id_or_name("") is None
