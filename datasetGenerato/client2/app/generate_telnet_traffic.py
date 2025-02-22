import socket
import time
import os
import random
from scapy.all import IP, UDP, TCP, send

# TELNET server details
TELNET_HOST = "serverTELNET"
TELNET_PORT = 23

# Number of iterations
ITERATIONS = 10

def generate_telnet_traffic():
    for i in range(ITERATIONS):
        try:
            print(f"Connecting to TELNET server (iteration {i + 1})...")
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((TELNET_HOST, TELNET_PORT))
                message = f"Hello from iteration {i + 1}\n".encode()
                s.sendall(message)

                response = s.recv(1024)
                # Filter out Telnet negotiation bytes (0xFF)
                response = response.replace(b'\xff', b'')
                print("Received:", response.decode(errors='ignore'))

            time.sleep(1)

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)  # Retry after a short delay

def generate_port_scan():
    target_ip = "172.18.0.7"
    nmap_command = f"nmap -sS -A -p- {target_ip}"
    os.system(nmap_command)


# Funzione per generare traffico di DoS
def generate_dos(n_packets=1000):
    target_ip = '172.18.0.7'
    for _ in range(n_packets):
        pkt = IP(dst=target_ip) / UDP(dport=random.choice([80, 443, 22]))
        send(pkt, verbose=False)
        time.sleep(0.01)

def generate_ping():
    target_ip = "172.18.0.7"
    nmap_command = f"ping {target_ip}"
    os.system(nmap_command)


if __name__ == "__main__":
    time.sleep(10)  # Delay to wait for server startup
    #generate_telnet_traffic()
    generate_port_scan()
    #generate_dos()
    #generate_ping()
