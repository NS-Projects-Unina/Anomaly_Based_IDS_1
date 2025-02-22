FROM ubuntu:latest

# Install BIND9
RUN apt-get update && apt-get install -y bind9

# Copy the named configuration file
COPY named.conf /etc/bind/named.conf

# Copy the zone file
COPY db.example.com /etc/bind/db.example.com

# Run the DNS server in the foreground
CMD ["named", "-g", "-c", "/etc/bind/named.conf"]
