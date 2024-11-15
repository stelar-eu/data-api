from flask import request, jsonify, current_app
from apiflask import APIBlueprint, HTTPTokenAuth
from keycloak import KeycloakAdmin,KeycloakPostError
import keycloak_module as kc
import minIO_module as minio
import reconciliation_module as rec
import yaml_processing_module as yproc
import monitor_module as mon
import sys

import schema



auth_tool_bp = APIBlueprint('auth_tool_blueprint', __name__,tag='Authorization Tool')


@auth_tool_bp.route('/data_layout', methods=['POST'])
@auth_tool_bp.input(schema.Identifier, location='json', example={"id":"test_data_api_1"})
@auth_tool_bp.output(schema.ResponseOK, status_code=200)
@auth_tool_bp.doc(tags=['Authorization Tool'], security=security_doc)
def create_data_layout():
    print("Hello World")