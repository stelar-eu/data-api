#!/bin/bash

# Ensure required environment variables are set
if [ -z "$MINIO_DOMAIN" ] || [ -z "$MINIO_ROOT_USER" ] || [ -z "$MINIO_ROOT_PASSWORD" ]; then
  echo "Error: MINIO_DOMAIN, MINIO_ROOT_USER, and MINIO_ROOT_PASSWORD must be set."
  exit 1
fi

# Configure MinIO alias using mc
mc alias set myminio "$MINIO_DOMAIN" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"
if [ $? -ne 0 ]; then
  echo "Failed to configure MinIO alias. Please check the provided environment variables."
  exit 1
fi

# Start Flask application
flask run