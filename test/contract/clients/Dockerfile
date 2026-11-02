FROM python:3.12-slim
COPY requirements.txt /clients/requirements.txt
RUN pip install --no-cache-dir -r /clients/requirements.txt
COPY . /clients
WORKDIR /clients
CMD ["pytest", "-v", "-rA"]
