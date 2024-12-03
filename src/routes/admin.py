from flask import request, jsonify, current_app, session
from apiflask import APIBlueprint
from src.auth import auth, security_doc
import re
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakPutError
import random
import smtplib, ssl
import logging
from email_validator import validate_email, EmailNotValidError
import kutils 
import datetime


admin_bp = APIBlueprint('admin_blueprint', __name__, enable_openapi=False)

    
@admin_bp.route('/users/count', methods=['GET'])
def get_user_count():
    try:
        # Initialize KeycloakAdmin client with refresh token
        keycloak_admin = kutils.init_admin_client_with_credentials()

        # Fetch the total number of users in Keycloak
        total_user_count = keycloak_admin.users_count()

        # Return the user count in a JSON response
        return jsonify({"user_count": total_user_count})
    
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 401
    except RuntimeError as re:
        return jsonify({'error': str(re)}), 500

  
@admin_bp.route('/users/<user_id>', methods=['GET', 'PUT'])
def handle_user(user_id):
    if request.method == 'GET':
        # Handle GET request - Fetch user details from Keycloak
        try:
            keycloak_admin = kutils.init_admin_client_with_credentials()
            user = keycloak_admin.get_user(user_id=user_id)

            if not user:
                return jsonify({'error': 'User not found'}), 400

            created_timestamp = user.get('createdTimestamp')
            creation_date = None
            if created_timestamp:
                creation_date = datetime.datetime.fromtimestamp(created_timestamp / 1000.0).strftime('%d-%m-%Y')

            roles = kutils.get_user_roles(user.get("id"), keycloak_admin)
            filtered_roles = [role for role in roles if role != 'default-roles-master']

            active_status = user.get('enabled', False)

            user_info = {
                "username": user.get("username"),
                "email": user.get("email"),
                "fullname": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                "joined_date": creation_date,
                "user_id": user.get("id"),
                "roles": filtered_roles,
                "active": active_status
            }

            return jsonify(user_info)

        except ValueError as ve:
            return jsonify({'error': str(ve)}), 401
        except RuntimeError as re:
            return jsonify({'error': str(re)}), 500

    elif request.method == 'PUT':
        try:
            data = request.get_json()
            user_id_json = data.get('userId')
            username = data.get('username')
            fullname = data.get('fullname')
            email = data.get('email')
            roles = data.get('roles')  # List of new roles
            active_account = data.get('activeAccount')

            if user_id_json != user_id:
                return jsonify({"success": False, "message": "User ID mismatch"}), 400

            # Initialize KeycloakAdmin client
            keycloak_admin = kutils.init_admin_client_with_credentials()

            # Fetch user details by user_id
            user = keycloak_admin.get_user(user_id=user_id)

            if not user:
                return jsonify({"success": False, "message": "User not found"}), 400

            # Prevent modifications to the "admin" username
            if user.get('username') == 'admin':
                return jsonify({"success": False, "message": "Modifications to the 'admin' account are not allowed."}), 403

            updated_info = {}
            
            # Check for username or email conflicts
            if username:
                users_with_same_username = keycloak_admin.get_users({'username': username})
                if any(u['id'] != user_id for u in users_with_same_username):
                    return jsonify({"success": False, "message": f"Username '{username}' is already in use."}), 400

                updated_info['username'] = username

            if email:
                users_with_same_email = keycloak_admin.get_users({'email': email})
                if any(u['id'] != user_id for u in users_with_same_email):
                    return jsonify({"success": False, "message": f"Email '{email}' is already in use."}), 400

                updated_info['email'] = email
                updated_info['emailVerified'] = True

            if fullname:
                name_parts = fullname.split()
                updated_info['firstName'] = name_parts[0]
                updated_info['lastName'] = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''

            if active_account:
                active_account_bool = str(active_account).lower() == 'true'
                updated_info['enabled'] = active_account_bool

            # Update user information
            keycloak_admin.update_user(user_id, payload=updated_info)

            # Handle role changes
            current_roles = keycloak_admin.get_realm_roles_of_user(user_id)  # Get the current roles of the user
            current_role_names = [role['name'] for role in current_roles if role['name'] != 'default-roles-master']  # Exclude default roles

            if roles is not None:
                if not roles:
                    # No roles specified: Unassign all non-default roles
                    roles_to_remove = [role for role in current_roles if role['name'] != 'default-roles-master']
                    if roles_to_remove:
                        keycloak_admin.delete_realm_roles_of_user(user_id, roles_to_remove)
                else:
                    # Unassign roles not in the request
                    roles_to_remove = [role for role in current_roles if role['name'] not in roles and role['name'] != 'default-roles-master']
                    if roles_to_remove:
                        keycloak_admin.delete_realm_roles_of_user(user_id, roles_to_remove)

                    # Assign new roles that are not already assigned
                    available_realm_roles = keycloak_admin.get_realm_roles()  # Fetch all available realm roles
                    roles_to_add = []
                    for role in roles:
                        if role not in current_role_names:
                            role_info = next((r for r in available_realm_roles if r['name'] == role), None)
                            if role_info:
                                roles_to_add.append(role_info)
                            else:
                                return jsonify({"success": False, "message": f"Role '{role}' not found in realm roles"}), 404

                    if roles_to_add:
                        keycloak_admin.assign_realm_roles(user_id, roles_to_add)

            return jsonify({"success": True, "message": f"User {user_id} successfully updated", "user": user_id}), 200

        except KeycloakPutError as ke:
            return jsonify({"success": False, "message": f"Failed to update user {user_id}", "error": str(ke)}), 500
        except ValueError as ve:
            return jsonify({'error': str(ve)}), 401
        except RuntimeError as re:
            return jsonify({'error': str(re)}), 500



