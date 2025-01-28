FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

COPY app/server.py .
COPY modello_addestrato.joblib .

RUN apt-get update && \
    apt-get install -y iptables python3-pip vsftpd apache2 openssh-server openbsd-inetd telnetd bind9 dnsutils postfix && \
    pip3 install flask scapy pandas joblib scikit-learn && \
    rm -rf /var/lib/apt/lists/* /tmp/*

# Configura vsftpd per consentire accessi anonimi senza chroot
RUN echo "anonymous_enable=YES" >> /etc/vsftpd.conf && \
    echo "anon_root=/var/ftp" >> /etc/vsftpd.conf && \
    echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf && \
    echo "write_enable=YES" >> /etc/vsftpd.conf && \
    echo "anon_upload_enable=YES" >> /etc/vsftpd.conf && \
    echo "anon_mkdir_write_enable=YES" >> /etc/vsftpd.conf && \
    mkdir -p /var/ftp/uploads && \
    chown ftp:ftp /var/ftp/uploads && \
    chmod 777 /var/ftp/uploads

# Configura SSH
RUN mkdir /var/run/sshd && \
    echo 'root:root' | chpasswd && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Configura Telnet
RUN echo "telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd" >> /etc/inetd.conf

# Configura DNS
RUN echo "zone \"example.com\" { type master; file \"/etc/bind/db.example.com\"; };" >> /etc/bind/named.conf.local && \
    echo "\$TTL    604800" > /etc/bind/db.example.com && \
    echo "@       IN      SOA     ns.example.com. root.example.com. (" >> /etc/bind/db.example.com && \
    echo "                              2         ; Serial" >> /etc/bind/db.example.com && \
    echo "                         604800         ; Refresh" >> /etc/bind/db.example.com && \
    echo "                          86400         ; Retry" >> /etc/bind/db.example.com && \
    echo "                        2419200         ; Expire" >> /etc/bind/db.example.com && \
    echo "                         604800 )       ; Negative Cache TTL" >> /etc/bind/db.example.com && \
    echo ";" >> /etc/bind/db.example.com && \
    echo "@       IN      NS      ns.example.com." >> /etc/bind/db.example.com && \
    echo "ns      IN      A       127.0.0.1" >> /etc/bind/db.example.com && \
    echo "www     IN      A       127.0.0.1" >> /etc/bind/db.example.com

# Configura Postfix per SMTP
RUN echo "smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)" > /etc/postfix/main.cf && \
    echo "biff = no" >> /etc/postfix/main.cf && \
    echo "append_dot_mydomain = no" >> /etc/postfix/main.cf && \
    echo "myhostname = localhost" >> /etc/postfix/main.cf && \
    echo "mydestination = \$myhostname, localhost.\$mydomain, localhost" >> /etc/postfix/main.cf && \
    echo "relayhost =" >> /etc/postfix/main.cf && \
    echo "mynetworks = 127.0.0.0/8" >> /etc/postfix/main.cf && \
    echo "mailbox_size_limit = 0" >> /etc/postfix/main.cf && \
    echo "recipient_delimiter = +" >> /etc/postfix/main.cf && \
    echo "inet_interfaces = all" >> /etc/postfix/main.cf && \
    echo "inet_protocols = all" >> /etc/postfix/main.cf

# Avvia i servizi
RUN service apache2 start && \
    service vsftpd start && \
    service ssh start && \
    service openbsd-inetd start && \
    service named start && \
    service postfix start

CMD ["python3", "server.py"]