import os
import socket
import time
from scapy.all import IP, TCP, send

SERVER_ADDRESS = 'server'  # Server hostname
UDP_PORT = 65432  # UDP port

def generate_port_scan():
    target_ip = "172.18.0.4"
    nmap_command = f"nmap -sS -sV -p- {target_ip}"
    os.system(nmap_command)

def generate_udp_traffic():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for i in range(40):  # Send 40 UDP packets
            message = f"UDP Packet {i+1} from Client 2"
            sock.sendto(message.encode(), (SERVER_ADDRESS, UDP_PORT))
            print(f"Sent UDP: {message}")
            time.sleep(1)  # Wait for 1 second before sending the next packet

if __name__ == "__main__":
    generate_port_scan()