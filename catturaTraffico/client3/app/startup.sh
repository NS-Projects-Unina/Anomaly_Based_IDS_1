#!/bin/sh

# Attendere che il router sia attivo
sleep 10

# Rimuovere qualsiasi route predefinita
ip route del default

# Impostare il router come gateway predefinito
ip route add default via $(getent hosts router | awk '{ print $1 }')

# Eliminare la route diretta alla subnet
ip route del 172.18.0.0/16

# Creare la directory rt_tables, se non esiste
mkdir -p /etc/iproute2

# Aggiungere la tabella di routing personalizzata
echo "100 custom" > /etc/iproute2/rt_tables

# Aggiungere una regola per far passare tutto il traffico locale attraverso il router
ip rule add from 172.18.0.0/16 lookup custom
ip route add 172.18.0.0/16 via $(getent hosts router | awk '{ print $1 }') table custom

# Verificare le route
ip rule show
ip route show table custom
ip route

# Eseguire lo script Python per generare traffico di traceroute
/venv/bin/python generate_dns_traffic.py
