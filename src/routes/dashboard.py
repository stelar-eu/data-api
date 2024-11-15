from flask import request, jsonify, current_app, session, make_response, render_template, redirect, url_for
from apiflask import APIBlueprint
from keycloak import KeycloakOpenID, KeycloakAdmin
import datetime
import json
import requests
import kutils 

#FOR TESTING ONLY!!!
import os

dashboard_bp = APIBlueprint('dashboard_blueprint', __name__, tag='Dashboard Operations')


# DEVELOPMENT ONLY FOR AWS CLUSTERS: Decide which partner the cluster corresponds to 
def get_partner_logo():
    domain = os.getenv("KLMS_DOMAIN_NAME","")

    PARTNER_IMAGE = None

    if domain:
        if 'vista' in domain.lower():
            PARTNER_IMAGE = url_for('static', filename='logos/vista.png')
        elif 'abaco' in domain.lower():
            PARTNER_IMAGE = url_for('static', filename='logos/abaco.png')
        elif 'ak' in domain.lower():
            PARTNER_IMAGE = url_for('static', filename='logos/ak.png')

    return PARTNER_IMAGE


# Initialize Keycloak client
def init_keycloak_client():
    config = current_app.config['settings']
    
    keycloak_openid = KeycloakOpenID(
        server_url=config['KEYCLOAK_URL'],
        client_id=config['KEYCLOAK_CLIENT_ID'],
        realm_name=config['REALM_NAME'],
        client_secret_key=config['KEYCLOAK_CLIENT_SECRET']
    )
    
    return keycloak_openid

# Home page (redirect target after login)
@dashboard_bp.route('/')
def dashboard_index():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    
    return render_template('index.html', PARTNER_IMAGE_SRC=get_partner_logo())

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
    
    return render_template('settings.html', PARTNER_IMAGE_SRC=get_partner_logo())

@dashboard_bp.route('/workflows')
def workflows():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    
    return render_template('workflows.html', PARTNER_IMAGE_SRC=get_partner_logo())

@dashboard_bp.route('/datasets')
def datasets():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    
    return render_template('datasets.html', PARTNER_IMAGE_SRC=get_partner_logo())


@dashboard_bp.route('/datasets/<dataset_id>')
def dataset_detail(dataset_id):
    
    config = current_app.config['settings']
    
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    
    package_metadata_url = f"{config['API_URL']}api/v1/catalog?id="
    metadata_url = package_metadata_url + dataset_id
    metadata_response = requests.get(metadata_url)
    if metadata_response.status_code == 200:
        metadata_data = metadata_response.json()
        if metadata_data.get("success", False):
            # Render the dataset detail page, passing the dataset object to the template
            return render_template('dataset_view.html', dataset=metadata_data, PARTNER_IMAGE_SRC=get_partner_logo())
        else:
            redirect(url_for('dashboard_blueprint.login'))
    else:
        redirect(url_for('dashboard_blueprint.login'))
    


@dashboard_bp.route('/admin-settings')
def adminSettings():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    if not 'admin' in session.get('USER_ROLES', []):
        return redirect(url_for('dashboard_blueprint.login'))
    
    return render_template('cluster.html', PARTNER_IMAGE_SRC=get_partner_logo())

####################################
# Login Route
####################################
@dashboard_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles the Authentication process of a user given his credentials.
    Talks with the specified Keycloak instance to authenticate the user and fetch
    his info (roles, name, username, etc). Inits an active session.
    """
    keycloak_openid = init_keycloak_client()

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
            try:
                # Request a token from Keycloak
                token = keycloak_openid.token(email, password)
                session['access_token'] = token['access_token']
                session['refresh_token'] = token['refresh_token']

                # Introspect the token to get user details
                userinfo = keycloak_openid.introspect(token['access_token'])

                if userinfo:
                    session['USER_NAME'] = userinfo.get('name')
                    session['USER_EMAIL'] = userinfo.get('email')
                    session['USER_USERNAME'] = userinfo.get('preferred_username')
                    session['ACTIVE'] = True
                    session['USER_ROLES'] = userinfo.get('realm_access', {}).get('roles', [])
                    session['KEYCLOAK_ID_USER'] = userinfo.get('sub')

                    # Fetch user creation date using client credentials
                    creation_date = kutils.fetch_user_creation_date(session['KEYCLOAK_ID_USER'])
                    if creation_date:
                        session['USER_CREATION_DATE'] = creation_date

                    # Redirect to home page
                    return redirect(url_for('dashboard_blueprint.dashboard_index'))
                else:
                    LOGIN_ERROR = True

            except Exception as e:
                # Handle exceptions during the token request
                LOGIN_ERROR = True

    # Pass error flags to the template. This is the login page frontend
    return render_template('login.html', 
                            EMPTY_EMAIL_ERROR=EMPTY_EMAIL_ERROR, 
                            EMPTY_PASSWORD_ERROR=EMPTY_PASSWORD_ERROR, 
                            LOGIN_ERROR=LOGIN_ERROR,
                            PARTNER_IMAGE_SRC=get_partner_logo())


####################################
# Logout Route
####################################
@dashboard_bp.route('/logout')
def logout():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))

    keycloak_openid = init_keycloak_client()

    # Revoke refresh token to log out
    try:
        keycloak_openid.logout(session['refresh_token'])
    except Exception as e:
       print(f"Error during logout: {e}")

    # Clear local session and redirect to the login page
    session.clear()
    return redirect(url_for('dashboard_blueprint.login'))

