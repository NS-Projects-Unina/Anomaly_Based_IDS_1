#!/bin/sh

# Remount /proc/sys as read-write
mount -o remount,rw /proc/sys

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Set up NAT using iptables
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

# Keep the container running
tail -f /dev/null &

# Eseguire lo script Python per monitorare il traffico
/venv/bin/python monitor.py
