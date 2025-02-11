FROM ubuntu:latest

# Install Nmap and other necessary packages
RUN apt update && apt install -y python3 python3-pip iproute2 nmap scapy iputils-ping\
    && apt clean && rm -rf /var/lib/apt/lists/*

# Verify Nmap installation
RUN nmap --version

# Remove specific IP route on container startup
RUN echo "ip route del 172.18.0.0/16" >> /root/.bashrc

# Copy the traffic generation script
COPY app/generate_telnet_traffic.py . 
COPY app/generate_traceroute_traffic.py .

# Copy the startup script
COPY app/startup.sh /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/startup.sh

# Run the startup script
CMD ["/usr/local/bin/startup.sh"]
