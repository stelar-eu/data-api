from flask import request, jsonify, current_app, session, make_response, render_template, redirect, url_for, flash
from apiflask import APIBlueprint
from keycloak import KeycloakOpenID, KeycloakAdmin
import datetime
import time
from auth import api_verify_token
import requests
import kutils 
from datetime import datetime, timedelta
from functools import wraps

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


def session_required(f):
    """
    Custom decorator to check if the session is active and the token is valid.
    If the session is invalid or token is expired, redirect to login with a default message.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if session is active
        if 'ACTIVE' not in session or not session['ACTIVE']:
            flash("Session Expired, Please Login Again","warning") 
            return redirect(url_for('dashboard_blueprint.login', next=request.url))

        # Retrieve token from session
        access_token = session.get('access_token')

        # If token doesn't exist or is invalid, clear session and redirect to login with a message
        if not access_token or not api_verify_token(access_token):
            session.clear() 
            flash("Session Expired, Please Login Again","warning") 
            return redirect(url_for('dashboard_blueprint.login', next=request.url))

        # If token is valid, continue with the requested function
        return f(*args, **kwargs)
    
    return decorated_function


# Home page (redirect target after login)
@dashboard_bp.route('/')
@session_required
def dashboard_index():
    return render_template('index.html', PARTNER_IMAGE_SRC=get_partner_logo())


# Signup Route
@dashboard_bp.route('/signup')
def signup():
    if 'ACTIVE' not in session or not session['ACTIVE']:
        return redirect(url_for('dashboard_blueprint.login'))
    return f"Welcome {session.get('USER_NAME', 'User')}"


# Settings Route
@dashboard_bp.route('/settings')
@session_required
def settings():    
    return render_template('settings.html', PARTNER_IMAGE_SRC=get_partner_logo())


@dashboard_bp.route('/workflows')
@session_required
def workflows():
    config = current_app.config['settings']
    
    headers = {
        'Authorization': f"Bearer {session.get('access_token')}"
    }
    wf_metadata_url = f"{config['API_URL']}api/v1/workflows"
    metadata_response = requests.get(wf_metadata_url, headers=headers)
    wf_metadata = metadata_response.json()

    if metadata_response.status_code == 200:
        if wf_metadata['result']:
            status_counts = {}
            monthly_counts = {}

            for wf in wf_metadata['result']:
                # Count workflow status for pie chart
                status = wf['state']
                status_counts[status] = status_counts.get(status, 0) + 1

                # Count workflows per month for bar chart
                start_date = wf['start_date']
                month_year = start_date[:7]  # Get "YYYY-MM" from "YYYY-MM-DDTHH:MM:SS"
                monthly_counts[month_year] = monthly_counts.get(month_year, 0) + 1

            # Get the last two months + current month for bar chart display
            today = datetime.today()
            months_to_display = [(today - timedelta(days=30 * i)).strftime('%Y-%m') for i in range(2, -1, -1)]
            
            # Ensure monthly_counts includes all three months (set to 0 if missing)
            monthly_counts = {month: monthly_counts.get(month, 0) for month in months_to_display}

            return render_template('workflows.html', 
                                workflows = wf_metadata['result'],
                                status_counts=status_counts,
                                monthly_counts=monthly_counts,
                                PARTNER_IMAGE_SRC=get_partner_logo())
        else:
            return redirect(url_for('dashboard_blueprint.login'))
    else:
        return redirect(url_for('dashboard_blueprint.login'))



@dashboard_bp.route('/workflows/<workflow_id>')
@session_required
def workflow(workflow_id):
    config = current_app.config['settings']
    
    # Basic input validation
    if not workflow_id:
        return redirect(url_for('dashboard_blueprint.datasets'))
    
    headers = {
        'Authorization': f"Bearer {session.get('access_token')}"
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
        return redirect(url_for('dashboard_blueprint.login'))    
    if tasks_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.login'))

    if wf_metadata['metadata'] and wf_tasks:
        # Sort tasks based on start date
        if wf_tasks['result']:
            wf_tasks['result'] = sorted(wf_tasks['result'], key=lambda x: x["start_date"])
        try:
            package_id = wf_metadata['metadata']['tags'].get('package_id')
        except:
            package_id = "Not specified"

        return render_template('workflow.html', workflow_id = workflow_id,
                                                PARTNER_IMAGE_SRC=get_partner_logo(),
                                                wf_metadata = wf_metadata,
                                                wf_tasks = wf_tasks.get('result', None),
                                                package_id = package_id)
    else:
        return redirect(url_for('dashboard_blueprint.login'))


@dashboard_bp.route('/task/<workflow_id>/<task_id>')
@session_required
def task(workflow_id, task_id):
    config = current_app.config['settings']

    # Basic input validation
    if not workflow_id or not task_id:
        return redirect(url_for('dashboard_blueprint.login'))
    
    headers = {
        'Authorization': f"Bearer {session.get('access_token')}"
    }

    # Request to fetch task metadata with authorization token
    task_metadata_url = f"{config['API_URL']}api/v1/task/execution/read?id="
    metadata_url = task_metadata_url + task_id
    metadata_response = requests.get(metadata_url, headers=headers)
    if metadata_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.login'))

    metadata_json = metadata_response.json()

    # Check if metadata is valid
    if not metadata_json.get("success", False):
        return redirect(url_for('dashboard_blueprint.login'))

    # Check if the metadata corresponds to the correct workflow
    if metadata_json.get('result').get('metadata').get('workflow_exec_id') != workflow_id:
        return redirect(url_for('dashboard_blueprint.login'))

    # Request to fetch task input data with authorization token
    task_input_url = f"{config['API_URL']}api/v1/task/execution/input_json?id="
    input_url = task_input_url + task_id
    input_response = requests.get(input_url, headers=headers)
    if input_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.login'))

    input_json = input_response.json()

    # Request to fetch task logs with authorization token
    job_logs_url = f"{config['API_URL']}api/v1/task/runtime/read?id="
    logs_url = job_logs_url + task_id
    logs_response = requests.get(logs_url, headers=headers)
    if logs_response.status_code != 200:
        return redirect(url_for('dashboard_blueprint.login'))

    logs_json = logs_response.json()

    # Finally render the page if everything is correct
    if input_json.get("success", False):
        return render_template('task.html', PARTNER_IMAGE_SRC=get_partner_logo(),
                               task_id=task_id,
                               workflow_id=workflow_id,
                               task_metadata=metadata_json['result'],
                               task_input=input_json['result'],
                               logs=logs_json)
    
    return redirect(url_for('dashboard_blueprint.login'))


@dashboard_bp.route('/datasets')
@session_required
def datasets():    
    return render_template('datasets.html', PARTNER_IMAGE_SRC=get_partner_logo())


@dashboard_bp.route('/datasets/<dataset_id>')
@session_required
def dataset_detail(dataset_id):
    
    config = current_app.config['settings']
    
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
@session_required
def adminSettings():
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
    keycloak_openid = kutils.initialize_keycloak_openid()

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

                    # After login, redirect to the original page (if provided)
                    next_url = request.args.get('next')
                    if next_url:
                        return redirect(next_url)
                    else:
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

    keycloak_openid = kutils.initialize_keycloak_openid()

    # Revoke refresh token to log out
    try:
        keycloak_openid.logout(session['refresh_token'])
    except Exception as e:
       print(f"Error during logout: {e}")

    # Clear local session and redirect to the login page
    session.clear()
    return redirect(url_for('dashboard_blueprint.login'))

