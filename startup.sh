#!/bin/sh 
cp config_file.yaml config.yaml
sed -i "s/^FLASK_RUN_PORT: .*/FLASK_RUN_PORT: ${SERVICE_PORT}/" config.yaml
sed -i "s|^CKAN_API: .*|CKAN_API: ${CKAN_SITE_URL}/api/3/action/|" config.yaml
sed -i "s/^dbname: .*/dbname: ${POSTGRES_DB}/" config.yaml
sed -i "s/^dbuser: .*/dbuser: ${POSTGRES_USER}/" config.yaml
sed -i "s/^dbpass: .*/dbpass: ${POSTGRES_PASSWORD}/" config.yaml
sed -i "s/^dbhost: .*/dbhost: ${POSTGRES_HOST}/" config.yaml
sed -i "s/^dbport: .*/dbport: ${POSTGRES_PORT}/" config.yaml
sed -i "s|^SPARQL_ENDPOINT: .*|SPARQL_ENDPOINT: ${SPARQL_ENDPOINT}|" config.yaml
sed -i "s|^API_URL: .*|API_URL: ${API_URL}|" config.yaml
sed -i "s|^MINIO_BUCKET: .*|MINIO_BUCKET: ${MINIO_BUCKET}|" config.yaml
sed -i "s|^MINIO_ENDPOINT: .*|MINIO_ENDPOINT: ${MINIO_ENDPOINT}|" config.yaml
sed -i "s|^MINIO_SECRET_KEY: .*|MINIO_SECRET_KEY: ${MINIO_SECRET_KEY}|" config.yaml
sed -i "s|^MINIO_ACCESS_KEY: .*|MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY}|" config.yaml
#exec python3 src/data_api.py config.yaml
# flask -A data_api:create_app --debug run -h 0.0.0.0 -p 80
gunicorn -w 4 -b 0.0.0.0:80 src.wsgi:app
# For debugging only
sleep 1d
