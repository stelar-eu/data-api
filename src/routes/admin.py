from flask import request, jsonify, current_app, session
from apiflask import APIBlueprint
from src.auth import auth, security_doc
import re
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError
import random
import smtplib, ssl
import logging
from email_validator import validate_email, EmailNotValidError
import kutils 
import datetime

logging.basicConfig(level=logging.INFO)  # Set up logging configuration


admin_bp = APIBlueprint('admin_blueprint', __name__, tag='Cluster Administration')

@admin_bp.route('/users/roles', methods=['GET'])
def get_realm_roles():
    try:
        # Initialize KeycloakAdmin client with refresh token or admin credentials
        keycloak_admin = kutils.init_admin_client('admin', 'stelartuc')

        # Get the optional 'brief_representation' and 'search_text' parameters from the request
        brief_representation = request.args.get('brief_representation', 'true').lower() == 'true'

        # Fetch the roles from Keycloak
        roles = keycloak_admin.get_realm_roles(brief_representation=brief_representation)

        # Return the roles in a JSON response
        return jsonify({"roles": roles})

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 401
    except RuntimeError as re:
        return jsonify({'error': str(re)}), 500

    
@admin_bp.route('/users/count', methods=['GET'])
def get_user_count():
    try:
        # Initialize KeycloakAdmin client with refresh token
        keycloak_admin = kutils.init_admin_client('admin', 'stelartuc')

        # Fetch the total number of users in Keycloak
        total_user_count = keycloak_admin.users_count()

        # Return the user count in a JSON response
        return jsonify({"user_count": total_user_count})
    
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 401
    except RuntimeError as re:
        return jsonify({'error': str(re)}), 500


@admin_bp.route('/users', methods=['GET'])
def get_users():
    try:
        # Initialize KeycloakAdmin client with refresh token
        keycloak_admin = kutils.init_admin_client('admin','stelartuc')

        # Get pagination values
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', 8))

        # Fetch users from Keycloak with pagination
        users = keycloak_admin.get_users(query={"first": offset, "max": limit})
        
        result = []
        for user in users:
            # Convert the createdTimestamp to a human-readable date
            created_timestamp = user.get('createdTimestamp')
            creation_date = None
            if created_timestamp:
                creation_date = datetime.datetime.fromtimestamp(created_timestamp / 1000.0).strftime('%d-%m-%Y')

            # Get roles and exclude 'default-roles-master'
            roles = kutils.get_user_roles(user.get("id"), keycloak_admin)
            filtered_roles = [role for role in roles if role != 'default-roles-master']
            
            # Check if the user is active or not (enabled field)
            active_status = user.get('enabled', False)  # Defaults to False if not present

            # Create the user information object
            user_info = {
                "username": user.get("username"),
                "email": user.get("email"),
                "fullname": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                "joined_date": creation_date,  # use the converted date
                "user_id": user.get("id"),
                "roles": filtered_roles,  # use filtered roles
                "active": active_status  # Include active status (true/false)
            }
            result.append(user_info)
        
        return jsonify(result)
    
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 401
    except RuntimeError as re:
        return jsonify({'error': str(re)}), 500

  
@admin_bp.route('/users/<user_id>', methods=['GET'])
def get_user_by_id(user_id):
    try:
        # Initialize KeycloakAdmin client with refresh token
        keycloak_admin = kutils.init_admin_client('admin', 'stelartuc')

        # Fetch user details by user_id
        user = keycloak_admin.get_user(user_id=user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 400  # Return 400 Bad Request if user not found

        # Convert the createdTimestamp to a human-readable date
        created_timestamp = user.get('createdTimestamp')
        creation_date = None
        if created_timestamp:
            creation_date = datetime.datetime.fromtimestamp(created_timestamp / 1000.0).strftime('%d-%m-%Y')

        # Get roles and exclude 'default-roles-master'
        roles = kutils.get_user_roles(user.get("id"), keycloak_admin)
        filtered_roles = [role for role in roles if role != 'default-roles-master']

        # Check if the user is active or not (enabled field)
        active_status = user.get('enabled', False)  # Defaults to False if not present

        # Create the user information object
        user_info = {
            "username": user.get("username"),
            "email": user.get("email"),
            "fullname": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
            "joined_date": creation_date,  # use the converted date
            "user_id": user.get("id"),
            "roles": filtered_roles,  # use filtered roles
            "active": active_status  # Include active status (true/false)
        }

        return jsonify(user_info)

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 401
    except RuntimeError as re:
        return jsonify({'error': str(re)}), 500

