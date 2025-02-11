FROM alpine

# Install necessary packages
RUN apk add --no-cache python3 py3-pip iproute2 \
    && apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev \
    && python3 -m venv /venv \
    && /venv/bin/pip install dnspython \
    && apk del .build-deps

RUN echo "ip route del 172.18.0.0/16" >> /root/.bashrc


# Copy the traffic generation script
COPY app/generate_dns_traffic.py .
COPY app/generate_traceroute_traffic.py .

# Copy the startup script
COPY app/startup.sh /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/startup.sh

# Run the startup script
CMD ["/usr/local/bin/startup.sh"]
