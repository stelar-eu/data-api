FROM python:3.10
WORKDIR /app
COPY . /app/
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["sh", "-c", "chmod +x configure.sh && ./configure.sh && exec python3 ./src/data_api.py config-example.yaml"]
