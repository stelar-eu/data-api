from cutils import ORGANIZATION
from kutils import get_user
from wxutils import PROCESS

#  The followng fixes a bug in FlaskClient !!
# werkzeug.__version__ = "3.1.3"


def test_process_creation(app):
    with app.app_context():
        stelar_klms = ORGANIZATION.get_entity("stelar-klms")
        assert stelar_klms is not None
        assert stelar_klms["name"] == "stelar-klms"
        assert stelar_klms["type"] == "organization"
        assert stelar_klms["name"] == "stelar-klms"

        johndoe = get_user("johndoe")

        proc = PROCESS.create_process(
            johndoe, organization="stelar-klms", title="Test Process Description"
        )
        assert proc is not None
        print(proc)
        assert proc["title"] == "Test Process Description"
        assert proc["owner_org"] == stelar_klms["id"]

        proc2 = PROCESS.get_entity(proc["id"])
        proc3 = PROCESS.get_entity(proc2["name"])
        assert proc2 == proc3
        assert proc2["title"] == "Test Process Description"
        assert proc2["owner_org"] == stelar_klms["id"]
        assert proc2["name"] == proc["name"]
        assert proc2["id"] == proc["id"]
