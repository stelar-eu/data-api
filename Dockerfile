FROM python:3.10
WORKDIR /app
COPY . /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN sed -i "s/^FLASK_RUN_PORT: .*/FLASK_RUN_PORT: $SERVICE_PORT/" config-example.yaml
RUN sed -i "s|^CKAN_API: .*|CKAN_API: $CKAN_SITE_URL/api/3/action/|" config-example.yaml
RUN sed -i "s/^dbname: .*/dbname: $POSTGRES_DB/" config-example.yaml
RUN sed -i "s/^dbuser: .*/dbuser: $POSTGRES_USER/" config-example.yaml
RUN sed -i "s/^dbpass: .*/dbpass: $POSTGRES_PASSWORD/" config-example.yaml
RUN sed -i "s/^dbhost: .*/dbhost: $POSTGRES_HOST/" config-example.yaml
RUN sed -i "s/^dbport: .*/dbport: $POSTGRES_PORT/" config-example.yaml
RUN sed -i "s|^SPARQL_ENDPOINT: .*|SPARQL_ENDPOINT: https://stelar-klms.eu:$ONTOP_PORT/sparql|" config-example.yaml
RUN sed -i "s|^API_URL: .*|API_URL: https://stelar-klms.eu:$SERVICE_PORT/|" config-example.yaml
ENTRYPOINT ["python3", "./src/data_api.py"]