#! /bin/bash

cp config-example.yaml config.yaml

sed -i "s/^FLASK_RUN_PORT: .*/FLASK_RUN_PORT: ${SERVICE_PORT}/" config.yaml
sed -i "s|^CKAN_API: .*|CKAN_API: ${CKAN_SITE_URL}/api/3/action/|" config.yaml
sed -i "s/^dbname: .*/dbname: ${POSTGRES_DB}/" config.yaml
sed -i "s/^dbuser: .*/dbuser: ${POSTGRES_USER}/" config.yaml
sed -i "s/^dbpass: .*/dbpass: ${POSTGRES_PASSWORD}/" config.yaml
sed -i "s/^dbhost: .*/dbhost: ${POSTGRES_HOST}/" config.yaml
sed -i "s/^dbport: .*/dbport: ${POSTGRES_PORT}/" config.yaml
sed -i "s|^SPARQL_ENDPOINT: .*|SPARQL_ENDPOINT: ${SPARQL_ENDPOINT}|" config.yaml
sed -i "s|^API_URL: .*|API_URL: ${API_URL}|" config.yaml

#exec python3 src/data_api.py config.yaml
flask -A data_api:create_app --debug run -h 0.0.0.0 -p 80

# For debugging only
#sleep 1d
