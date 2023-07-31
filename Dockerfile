FROM python
WORKDIR /app
COPY . /app/
COPY requirements.txt .
COPY src/ /app/src/
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python3", "./src/data_api.py"]
