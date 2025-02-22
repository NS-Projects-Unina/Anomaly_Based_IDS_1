FROM ubuntu:latest

RUN apt-get update && apt-get install -y openbsd-inetd telnetd \
    && echo "telnet stream tcp nowait root /usr/sbin/telnetd telnetd -h" > /etc/inetd.conf

EXPOSE 23

CMD ["sh", "-c", "service openbsd-inetd start && tail -f /dev/null"]
