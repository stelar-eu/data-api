from flask import request, jsonify, current_app, session, make_response, render_template, redirect, url_for
import requests
from apiflask import APIBlueprint
import logging
from minio import Minio
from minio.error import S3Error
import mutils as mu

from routes.publisher import publisher_bp


dashboard_bp = APIBlueprint('dashboard_blueprint', __name__, tag='Dashboard Operations')


# Set Keycloak variables in session
def init_keycloak_session():
    # Fetch the Keycloak server details from the environment variables set during app init
    config = current_app.config['settings']

    session['KEYCLOAK_HOST'] = config['KEYCLOAK_URL']
    session['KEYCLOAK_BASE_URL'] = f"{session['KEYCLOAK_HOST']}/realms/{config['REALM_NAME']}"
    session['KEYCLOAK_CLIENT_ID'] = config['KEYCLOAK_CLIENT_ID']
    session['KEYCLOAK_CLIENT_SECRET'] = config['KEYCLOAK_CLIENT_SECRET'],
    session['KEYCLOAK_TOKEN_URL'] = f"{session['KEYCLOAK_BASE_URL']}/protocol/openid-connect/token"
    session['KEYCLOAK_INTROSPECT_URL'] = f"{session['KEYCLOAK_BASE_URL']}/protocol/openid-connect/token/introspect"

# Home page (redirect target after login)
@dashboard_bp.route('/')
def dashboard_index():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    

    return render_template('index.html')

# Signup Route
@dashboard_bp.route('/signup')
def signup():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    

    return f"Welcome {session.get('USER_NAME', 'User')}"


# Settings Route
@dashboard_bp.route('/settings')
def settings():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    

    return render_template('settings.html')
    

@dashboard_bp.route('/workflows')
def workflows():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    

    return render_template('workflows.html')

@dashboard_bp.route('/datasets')
def datasets():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    
    return render_template('upload.html')

# Login route
@dashboard_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles the Authentication process of a user given his credentials.
    Talks with the specified Keycloak instance to authenticate the user and fetch
    his info (roles, name, username, etc). Inits an active session.

    """
    init_keycloak_session()  # Initialize the Keycloak session variables

    EMPTY_EMAIL_ERROR = False
    EMPTY_PASSWORD_ERROR = False
    LOGIN_ERROR = False

    # Check if the user is already logged in and redirect him to console home page if so
    if request.method == 'GET':
        if 'ACTIVE' in session and session['ACTIVE']:
            return redirect(url_for('dashboard_blueprint.dashboard_index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic validation
        if not email:
            EMPTY_EMAIL_ERROR = True
        if not password:
            EMPTY_PASSWORD_ERROR = True

        # If no validation errors, proceed with login
        if not EMPTY_EMAIL_ERROR and not EMPTY_PASSWORD_ERROR:
            token_data = {
                'grant_type': 'password',
                'client_id': session['KEYCLOAK_CLIENT_ID'],
                'client_secret': session['KEYCLOAK_CLIENT_SECRET'],
                'username': email,
                'password': password,
            }

            try:
                # Request a token from Keycloak
                token_response = requests.post(session['KEYCLOAK_TOKEN_URL'], data=token_data)
                token_result = token_response.json()

                if 'access_token' in token_result:
                    # Store tokens in session
                    session['access_token'] = token_result['access_token']
                    session['refresh_token'] = token_result['refresh_token']

                    # Introspect the token
                    introspection_data = {
                        'token': session['access_token'],
                        'client_id': session['KEYCLOAK_CLIENT_ID'],
                        'client_secret': session['KEYCLOAK_CLIENT_SECRET'],
                    }
                    introspection_response = requests.post(session['KEYCLOAK_INTROSPECT_URL'], data=introspection_data)
                    token_info = introspection_response.json()

                    # Verify if token is active
                    if token_info.get('active'):
                        # Store user info in session
                        session['USER_NAME'] = token_info.get('name')
                        session['USER_EMAIL'] = token_info.get('email')
                        session['USER_USERNAME'] = token_info.get('preferred_username')
                        session['ACTIVE'] = True
                        session['USER_ROLES'] = token_info.get('realm_access', {}).get('roles', [])

                        # Redirect to home page
                        return redirect(url_for('dashboard_blueprint.dashboard_index'))
                    else:
                        LOGIN_ERROR = True
                else:
                    LOGIN_ERROR = True
            except Exception as e:
                # Handle exceptions during the token request
                LOGIN_ERROR = True


    # Pass error flags to the template. This is the login page frontend
    return render_template('login.html', 
                            EMPTY_EMAIL_ERROR=EMPTY_EMAIL_ERROR, 
                            EMPTY_PASSWORD_ERROR=EMPTY_PASSWORD_ERROR, 
                            LOGIN_ERROR=LOGIN_ERROR)


####################################
# IMPLEMENT Single sign out with keycloak too!!!!!
####################################
@dashboard_bp.route('/logout')
def logout():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    # Clear local session and redirect to the login page if no OAuth token is found
    session.clear()
    return redirect(url_for('dashboard_blueprint.login'))