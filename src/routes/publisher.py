import logging
import os

from apiflask import APIBlueprint
from flask import current_app, jsonify, make_response, request, session
from routes.generic import render_api_output
from backend.ckan import ckan_request
import schema
from minio import Minio
from minio.error import S3Error

import kutils
import mutils as mu
from auth import token_active

"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to publishing a Dataset
    both in S3 storage and CKAN Data Catalog
"""

# The tasks operations blueprint for all operations related to the lifecycle of `tasks
publisher_bp = APIBlueprint("pub_blueprint", __name__, enable_openapi=False)

logger = logging.getLogger(__name__)


@publisher_bp.route("/fetch_paths", methods=["GET"])
@token_active
def fetch_minio_paths():
    try:
        access_token = kutils.current_token()

        credentials = mu.get_temp_minio_credentials(access_token)
        # Now use the temporary credentials to list the paths the user has access to
        paths = mu.list_buckets_with_folders(credentials)

        return jsonify({"paths": paths})

    except ValueError as e:
        # Handle the case where no token is found, return 401 Unauthorized
        return make_response(
            {
                "success": False,
                "error": {"__type": "Authorization Error", "name": [str(e)]},
            },
            401,
        )

    except Exception as e:
        # Handle any other unexpected errors, return 500 Internal Server Error
        return make_response(
            {
                "success": False,
                "error": {"__type": "Unexpected Error", "name": [str(e)]},
            },
            500,
        )


@publisher_bp.route("/fetch_buckets", methods=["GET"])
@token_active
def fetch_buckets():
    try:
        access_token = kutils.current_token()

        credentials = mu.get_temp_minio_credentials(access_token)

        return mu.list_buckets(credentials)

    except Exception as e:
        # Handle any other unexpected errors, return 500 Internal Server Error
        return make_response(
            {
                "success": False,
                "error": {"__type": "Unexpected Error", "name": [str(e)]},
            },
            500,
        )


@publisher_bp.route("/stat_path", methods=["GET"])
@token_active
def stat_minio_path():
    try:
        access_token = kutils.current_token()
        credentials = mu.get_temp_minio_credentials(access_token)

        # Get the bucket and path parameters from the query string
        bucket_name = request.args.get("bucket")
        object_path = request.args.get("path")

        if not bucket_name:
            return jsonify({"error": "Bucket not specified"}), 400

        # If no path is provided or path is root, assume top level of the bucket
        if not object_path or object_path == "/":
            object_path = ""
        else:
            # Ensure the prefix ends with a '/' if provided
            object_path = (
                object_path if object_path.endswith("/") else object_path + "/"
            )

        config = current_app.config["settings"]
        minio_url = config["MINIO_API_SUBDOMAIN"] + "." + config["KLMS_DOMAIN_NAME"]

        client = Minio(
            minio_url,
            access_key=credentials["AccessKeyId"],
            secret_key=credentials["SecretAccessKey"],
            session_token=credentials["SessionToken"],
            secure=config["MC_INSECURE"] == "false",
        )

        # List objects at the given level (non-recursive)
        objects = list(
            client.list_objects(bucket_name, prefix=object_path, recursive=False)
        )

        directories = []
        files = []

        for obj in objects:
            try:
                stat_info = client.stat_object(bucket_name, obj.object_name)
                stat_dict = {
                    "size": stat_info.size,
                    "last_modified": stat_info.last_modified.isoformat(),
                    "etag": stat_info.etag,
                    "content_type": stat_info.content_type,
                }
            except S3Error:
                continue

            # Directories: keys ending with '/'
            if obj.object_name.endswith("/"):
                directories.append({"name": obj.object_name, "stats": stat_dict})
            else:
                files.append({"name": obj.object_name, "stats": stat_dict})

        directories_sorted = sorted(directories, key=lambda x: x["name"])
        files_sorted = sorted(files, key=lambda x: x["name"])

        ordered_list = directories_sorted + files_sorted

        return jsonify({"objects": ordered_list}), 200

    except S3Error as e:
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        return make_response(
            {
                "success": False,
                "error": {"__type": "Unexpected Error", "name": [str(e)]},
            },
            500,
        )


@publisher_bp.route("/autocomplete/<limit>/<query>", methods=["POST"])
@render_api_output(logger)
@token_active
def autocomplete_datasets(limit, query):
    return ckan_request(
        "package_autocomplete", method="POST", json={"q": query, "limit": limit}
    )


@publisher_bp.route("/upload_file", methods=["POST"])
@token_active
def upload_file_to_minio():
    try:
        # Get access token from Authorization header or session
        access_token = request.headers.get("Authorization")
        if access_token:
            access_token = access_token.replace("Bearer", "").strip()
        else:
            access_token = session.get("access_token")

        if not access_token:
            raise ValueError("No access token found in headers or session.")

        # Get temporary Minio credentials using the token
        credentials = mu.get_temp_minio_credentials(access_token)

        # Validate file upload
        if "file" not in request.files:
            return jsonify({"error": "No file specified"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        # Get bucket and destination path from the form data
        bucket_name = request.form.get("bucket")
        destination_path = request.form.get("path")
        if not bucket_name or not destination_path:
            return jsonify({"error": "Bucket or path not specified"}), 400

        # Construct the object name from the destination folder and uploaded filename
        folder = os.path.dirname(destination_path)
        object_name = os.path.join(folder, file.filename)

        # Ensure the object name does not accidentally include the bucket prefix
        bucket_prefix = bucket_name + "/"
        if object_name.startswith(bucket_prefix):
            object_name = object_name[len(bucket_prefix) :]

        logger.debug(
            "Uploading to bucket: %s, object key: %s", bucket_name, object_name
        )

        # Get MinIO client configuration from Flask config
        config = current_app.config["settings"]
        minio_url = config["MINIO_API_SUBDOMAIN"] + "." + config["KLMS_DOMAIN_NAME"]

        # Configure the client (adjust the secure flag as needed)
        client = Minio(
            minio_url,
            access_key=credentials["AccessKeyId"],
            secret_key=credentials["SecretAccessKey"],
            session_token=credentials["SessionToken"],
            secure=config["MC_INSECURE"] == "false",
        )

        # Upload the file to MinIO
        client.put_object(
            bucket_name,
            object_name,
            file.stream,
            length=-1,
            part_size=10 * 1024 * 1024,  # 10MB part size
        )
        return jsonify({"message": "File uploaded successfully!"}), 200

    except S3Error as e:
        logger.error("S3Error during file upload: %s", str(e))
        return jsonify({"error": str(e)}), 500

    except ValueError as e:
        logger.error("Authorization error: %s", str(e))
        return make_response(
            {
                "success": False,
                "error": {"__type": "Authorization Error", "name": [str(e)]},
            },
            401,
        )

    except Exception as e:
        logger.error("Unexpected error: %s", str(e))
        return make_response(
            {
                "success": False,
                "error": {"__type": "Unexpected Error", "name": [str(e)]},
            },
            500,
        )
