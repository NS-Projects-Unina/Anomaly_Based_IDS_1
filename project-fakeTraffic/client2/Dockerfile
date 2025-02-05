FROM ubuntu:20.04

WORKDIR /app

COPY app/client2.py .

RUN apt-get update && \
    apt-get install -y python3-pip nmap && \
    pip3 install scapy && \
    rm -rf /var/lib/apt/lists/* /tmp/*

CMD ["python3", "client2.py"]