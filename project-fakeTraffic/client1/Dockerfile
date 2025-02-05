FROM python:3.8-slim

WORKDIR /app

COPY app/client1.py .
COPY app/file.txt .

RUN pip install scapy requests

CMD ["python", "client1.py"]