FROM ubuntu:latest

# Install OpenSSH server
RUN apt-get update && apt-get install -y openssh-server

# Set root password
RUN echo "root:rootpassword" | chpasswd

# Configure SSH server
RUN mkdir /var/run/sshd

# Allow root login and password authentication
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Run SSH server in the foreground
CMD ["/usr/sbin/sshd", "-D"]
