import yaml
from authz_module import AuthorizationModule, ResourcePermissionsType, ResourceSpecPermissionsType

def test_alias():
    file = """
    roles:
      - name: "data_curator"
        permissions:
            - action: ["readwrite","writeds"]
              resource: "curated-zone/*"
            - action: "readwrite"
              resource: "consumption-zone/*"

      - name: "data_engineer"
        permissions:
          - action: "read"
            resource: "raw-zone/*"
          - action: "write"
            resource: "curated-zone/*"
          - action: "readwrite"
            resource: "consumption-zone/*"
          - action: "complex_alias"
            resource_spec:
              - type: "dataset"
                group: "foo1"
                capacity: "main"
              - group: "stelar-klms"
                capacity: "maintainer"

    actions:
        readwrite: ["update","edit_task"]
        writeds: ["read","delete","edit"]
        complex_alias: ["readwrite","writeds","delete_task"]
    """

    yaml_content = yaml.safe_load(file)
    for role in yaml_content["roles"]:
            for perm in role["permissions"]:
                match perm:
                    case {"action": a, "resource": p}:
                        perm = AuthorizationModule.alias_to_value(AuthorizationModule,perm, a, yaml_content)
                    case {"action": a, "resource_spec": spec}:
                        perm = AuthorizationModule.alias_to_value(AuthorizationModule,perm, a, yaml_content)
    
    print(yaml_content)

    assert yaml_content["roles"][0]["permissions"][0]["action"] == ["update", "edit_task", "read", "delete", "edit"]
    assert yaml_content["roles"][0]["permissions"][1]["action"] == ["update", "edit_task"]
    assert yaml_content["roles"][1]["permissions"][0]["action"] == "read"
    assert yaml_content["roles"][1]["permissions"][1]["action"] == "write"
    assert yaml_content["roles"][1]["permissions"][3]["action"] == ["update", "edit_task", "read", "delete", "edit","delete_task"]             

    

