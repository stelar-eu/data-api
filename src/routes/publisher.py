from flask import request, jsonify, current_app, session, make_response, render_template
from apiflask import APIBlueprint
import logging
from minio import Minio
from minio.error import S3Error
import os
import mutils as mu
from src.auth import auth, security_doc
import json

"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to publishing a Dataset
    both in S3 storage and CKAN Data Catalog
"""

# The tasks operations blueprint for all operations related to the lifecycle of `tasks
publisher_bp = APIBlueprint('pub_blueprint', __name__, tag='Dashboard Dataset')

logging.basicConfig(level=logging.DEBUG)
    
@publisher_bp.route('/fetch_paths', methods=['GET'])
@auth.login_required
def fetch_minio_paths():

    try:
        # Try to get the token from the Authorization header
        access_token = request.headers.get('Authorization')
        
        if access_token:
            # Token found in Authorization header, remove 'Bearer ' prefix
            access_token = access_token.replace("Bearer ", "")
        else:
            # No token in Authorization header, try to fetch from session
            access_token = session.get('access_token')
        
        # If access_token is still None, raise an exception
        if not access_token:
            raise ValueError("No access token found in headers or session.")
        
        credentials = mu.get_temp_minio_credentials(access_token)
        # Now use the temporary credentials to list the paths the user has access to
        paths = mu.list_buckets_with_folders(credentials)

        return jsonify({'paths': paths})

    except ValueError as e:
    # Handle the case where no token is found, return 401 Unauthorized
        return make_response({
            'success': False, 
            'error': {
                '__type': 'Authorization Error',
                'name': [str(e)]
            }
        }, 401)

    except Exception as e:
        # Handle any other unexpected errors, return 500 Internal Server Error
        return make_response({
            'success': False, 
            'error': {
                '__type': 'Unexpected Error',
                'name': [str(e)]
            }
        }, 500)


@publisher_bp.route('/upload_file', methods=['POST'])
@auth.login_required
def upload_file_to_minio():

    try:
        # Try to get the token from the Authorization header
        access_token = request.headers.get('Authorization')
        
        if access_token:
            # Token found in Authorization header, remove 'Bearer ' prefix
            access_token = access_token.replace("Bearer ", "")
        else:
            # No token in Authorization header, try to fetch from session
            access_token = session.get('access_token')
        
        # If access_token is still None, raise an exception
        if not access_token:
            raise ValueError("No access token found in headers or session.")
        
        credentials = mu.get_temp_minio_credentials(access_token)

        if 'file' not in request.files:
            return jsonify({'error': 'No file specified'}), 400

        file = request.files['file']
        destination_path = request.form.get('path')

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400


        if 'file' not in request.files:
                return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        bucket_name = request.form.get('bucket')  # Get the bucket from the form
        destination_path = request.form.get('path')  # Get the full path from the form

        if not bucket_name or not destination_path:
            return jsonify({'error': 'Bucket or path not specified'}), 400

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        try:
            bucket_prefix = bucket_name + '/'
            # Extract the folder from the cleaned destination path
            folder = os.path.dirname(destination_path)

            # Combine the folder with the filename to create the object name
            object_name = os.path.join(folder, file.filename)

            # Remove Bucket Prefix from Object Full Path (Avoid creating subfolder with the same name as the bucket)
            object_name.replace(bucket_prefix, '', 1)

            logging.debug(object_name)

            # Upload the file to MinIO
            config = current_app.config['settings']

            minio_url = config['MINIO_API_SUBDOMAIN'] + "." + config['KLMS_DOMAIN_NAME']

            client = Minio(
                minio_url,
                access_key=credentials['AccessKeyId'],
                secret_key=credentials['SecretAccessKey'],
                session_token=credentials['SessionToken'],
                secure=True  # Set to False if you are using HTTP instead of HTTPS
            )

            # Upload the file to MinIO in the specified bucket and path
            client.put_object(
                bucket_name,
                object_name,
                file.stream,
                length=-1,
                part_size=10*1024*1024  # 10MB part size
            )
            return jsonify({'message': 'File uploaded successfully!'}), 200

        except S3Error as e:
            return jsonify({'error': str(e)}), 500
    
    except ValueError as e:
    # Handle the case where no token is found, return 401 Unauthorized
        return make_response({
            'success': False, 
            'error': {
                '__type': 'Authorization Error',
                'name': [str(e)]
            }
        }, 401)

    except Exception as e:
        # Handle any other unexpected errors, return 500 Internal Server Error
        return make_response({
            'success': False, 
            'error': {
                '__type': 'Unexpected Error',
                'name': [str(e)]
            }
        }, 500)

