FROM python:3.12-slim
RUN pip install --no-cache-dir botocore==1.43.123
COPY simulator.py /simulator.py
CMD ["python", "-u", "/simulator.py"]
