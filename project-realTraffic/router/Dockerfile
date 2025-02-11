FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc iproute2 iptables python3-pip python3-venv

# Create a virtual environment
RUN python3 -m venv /venv

# Install Python dependencies in the virtual environment
RUN /venv/bin/pip install --no-cache-dir Flask scapy joblib pandas scikit-learn

# Copy the application files
COPY app/monitor.py .
COPY modello_addestrato.joblib .

# Copy the router setup script
COPY router-setup.sh /usr/local/bin/router-setup.sh

# Make the router setup script executable
RUN chmod +x /usr/local/bin/router-setup.sh

# Expose the application port
EXPOSE 5000

# Add necessary capabilities
RUN apt-get install -y libcap2-bin
RUN setcap cap_net_admin=eip /usr/sbin/sysctl

# Run the router setup script and start the monitor
CMD ["/bin/sh", "-c", "/usr/local/bin/router-setup.sh && /venv/bin/python /app/monitor.py"]
