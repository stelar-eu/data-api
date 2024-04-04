#!/bin/bash

sed -i "s/^FLASK_RUN_PORT: .*/FLASK_RUN_PORT: ${SERVICE_PORT}/" config-example.yaml
sed -i "s|^CKAN_API: .*|CKAN_API: ${CKAN_SITE_URL}/api/3/action/|" config-example.yaml
sed -i "s/^dbname: .*/dbname: ${POSTGRES_DB}/" config-example.yaml
sed -i "s/^dbuser: .*/dbuser: ${POSTGRES_USER}/" config-example.yaml
sed -i "s/^dbpass: .*/dbpass: ${POSTGRES_PASSWORD}/" config-example.yaml
sed -i "s/^dbhost: .*/dbhost: ${POSTGRES_HOST}/" config-example.yaml
sed -i "s/^dbport: .*/dbport: ${POSTGRES_PORT}/" config-example.yaml
sed -i "s|^SPARQL_ENDPOINT: .*|SPARQL_ENDPOINT: https://stelar-klms.eu:${ONTOP_PORT}/sparql|" config-example.yaml
sed -i "s|^API_URL: .*|API_URL: https://stelar-klms.eu:${SERVICE_PORT}/|" config-example.yaml

