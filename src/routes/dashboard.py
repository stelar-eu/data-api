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


@dashboard_bp.route('/workflow/<workflow_id>')
def workflow(workflow_id):
    config = current_app.config['settings']
    
    # Basic input validation
    if not workflow_id:
        return redirect(url_for('dashboard_blueprint.datasets'))
    
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    
    # Extract the access token from the session
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('dashboard_blueprint.login'))
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    wf_metadata_url = f"{config['API_URL']}api/v1/workflow/execution/read?id="
    metadata_url = wf_metadata_url + workflow_id
    metadata_response = requests.get(metadata_url, headers=headers)
    wf_metadata = metadata_response.json()

    wf_task_url = f"{config['API_URL']}api/v1/workflow/tasks?id="
    tasks_url = wf_task_url + workflow_id
    tasks_response = requests.get(tasks_url, headers=headers)
    wf_tasks = tasks_response.json()

    if metadata_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.datasets'))
    
    if tasks_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.datasets'))

    # Sort tasks based on start date
    if wf_tasks['result']:
        wf_tasks['result'] = sorted(wf_tasks['result'], key=lambda x: x["start_date"])

    return render_template('workflow.html', workflow_id = workflow_id,
                                            PARTNER_IMAGE_SRC=get_partner_logo(),
                                            wf_metadata = wf_metadata,
                                            wf_tasks = wf_tasks['result'])


@dashboard_bp.route('/task/<workflow_id>/<task_id>')
def task(workflow_id, task_id):
    config = current_app.config['settings']

    # Basic input validation
    if not workflow_id or not task_id:
        return redirect(url_for('dashboard_blueprint.datasets'))

    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))

    # Extract the access token from the session
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('dashboard_blueprint.login'))

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    # Request to fetch task metadata with authorization token
    task_metadata_url = f"{config['API_URL']}api/v1/task/execution/read?id="
    metadata_url = task_metadata_url + task_id
    metadata_response = requests.get(metadata_url, headers=headers)
    if metadata_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.datasets'))

    metadata_json = metadata_response.json()

    # Check if metadata is valid
    if not metadata_json.get("success", False):
        return redirect(url_for('dashboard_blueprint.datasets'))

    # Check if the metadata corresponds to the correct workflow
    if metadata_json.get('result').get('metadata').get('workflow_exec_id') != workflow_id:
        return redirect(url_for('dashboard_blueprint.datasets'))

    # Request to fetch task input data with authorization token
    task_input_url = f"{config['API_URL']}api/v1/task/execution/input_json?id="
    input_url = task_input_url + task_id
    input_response = requests.get(input_url, headers=headers)
    if input_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.datasets'))

    input_json = input_response.json()

    # Request to fetch task logs with authorization token
    job_logs_url = f"{config['API_URL']}api/v1/task/runtime/read?id="
    logs_url = job_logs_url + task_id
    logs_response = requests.get(logs_url, headers=headers)
    if logs_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.datasets'))

    logs_json = logs_response.json()

    # Finally render the page if everything is correct
    if input_json.get("success", False):
        return render_template('task.html', PARTNER_IMAGE_SRC=get_partner_logo(),
                               task_id=task_id,
                               workflow_id=workflow_id,
                               task_metadata=metadata_json['result'],
                               task_input=input_json['result'],
                               logs=logs_json)
    
    return redirect(url_for('dashboard_blueprint.datasets'))



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

