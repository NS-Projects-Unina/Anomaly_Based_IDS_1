import ftplib
import socket
import time
import requests
import smtplib
from scapy.all import IP, UDP, TCP, send

SERVER_ADDRESS = 'server'  # Server hostname
UDP_PORT = 65432  # UDP port
TCP_PORT = 65433  # TCP port
HTTP_PORT = 80    # HTTP port
SSH_PORT = 22     # SSH port
FTP_PORT = 21     # FTP port
TELNET_PORT = 23  # Telnet port
DNS_PORT = 53     # DNS port
SMTP_PORT = 25    # SMTP port
FINGER_PORT = 79  # Finger port

def generate_udp_traffic():
    for i in range(5):  # Send 20 UDP packets
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as sock:
            ip_packet = IP(dst=SERVER_ADDRESS) / UDP(dport=UDP_PORT) / f"UDP Packet {i+1} from Client 1"
            send(ip_packet)
            print(f"Sent UDP: UDP Packet {i+1} from Client 1")
            time.sleep(1)  # Wait for 1 second before sending the next packet


def generate_tcp_traffic():
    for i in range(5):  # Send 20 TCP packets
        for attempt in range(5):  # Retry up to 5 times
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((SERVER_ADDRESS, TCP_PORT))
                    message = f"TCP Packet {i+1} from Client 1"
                    sock.sendall(message.encode())
                    print(f"Sent TCP: {message}")
                    break  # Exit the retry loop if successful
            except ConnectionRefusedError:
                print(f"Connection refused, retrying ({attempt + 1}/5)...")
                time.sleep(2)  # Wait for 2 seconds before retrying
        time.sleep(1)  # Wait for 1 second before sending the next packet


def request_http_service():
    try:
        for i in range(5):  # Invia 5 richieste HTTP
            response = requests.get(f"http://{SERVER_ADDRESS}:{HTTP_PORT}")
            print(f"HTTP response {i+1}: {response.status_code}")
            time.sleep(1)  # Attendi 1 secondo tra le richieste
    except requests.RequestException as e:
        print(f"HTTP request failed: {e}")

def request_html_file():
    try:
        for i in range(5):
            response = requests.get(f"http://{SERVER_ADDRESS}/sample.html")
            if response.status_code == 200:
                print(f"HTML file retrieved successfully (Request {i+1})")
            else:
                print(f"Failed to retrieve HTML file (Request {i+1}): {response.status_code}")
            time.sleep(1)  # Wait for 1 second between requests
    except requests.RequestException as e:
        print(f"HTML request failed: {e}")

def request_ssh_service():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_ADDRESS, SSH_PORT))
        print("SSH connection established")
        while True:
            sock.send(b"SSH keep-alive data")
            print("Sent SSH keep-alive data")
            time.sleep(3)  # Invia dati ogni 3 secondi
    except socket.error as e:
        print(f"SSH connection failed: {e}")

def request_ftp_service():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_ADDRESS, FTP_PORT))
            print("FTP connection established")
            # Invia pacchetti FTP
            ftp = ftplib.FTP()
            ftp.connect(SERVER_ADDRESS, FTP_PORT)
            ftp.login('anonymous', '')  # Usa credenziali anonime
            ftp.cwd('uploads')  # Cambia la directory di lavoro
            with open("file.txt", "rb") as file:
                ftp.storbinary("STOR file.txt", file)
            ftp.quit()
            print("FTP packet sent")
    except socket.error as e:
        print(f"FTP connection failed: {e}")
    except ftplib.all_errors as e:
        print(f"FTP error: {e}")

def request_telnet_service():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_ADDRESS, TELNET_PORT))
            print("Telnet connection established")
            sock.send(b"Telnet test data")
            print("Sent Telnet test data")
    except socket.error as e:
        print(f"Telnet connection failed: {e}")

def request_dns_service():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01', (SERVER_ADDRESS, DNS_PORT))
            data, _ = sock.recvfrom(512)
            print(f"DNS response: {data}")
    except socket.error as e:
        print(f"DNS request failed: {e}")

def request_smtp_service():
    try:
        server = smtplib.SMTP(SERVER_ADDRESS, SMTP_PORT)
        server.sendmail('from@example.com', 'to@example.com', 'Subject: Test\n\nThis is a test email.')
        server.quit()
        print("SMTP email sent")
    except smtplib.SMTPException as e:
        print(f"SMTP request failed: {e}")

def request_finger_service():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_ADDRESS, FINGER_PORT))
            sock.send(b'\n')  # Richiesta finger per tutti gli utenti
            response = sock.recv(1024)
            print(f"Finger response: {response.decode()}")
    except socket.error as e:
        print(f"Finger request failed: {e}")

if __name__ == "__main__":
    time.sleep(5)  # devo aspettare che il server sia pronto
    request_html_file()
    generate_udp_traffic()
    generate_tcp_traffic()
    request_http_service()
    request_html_file()
    request_ssh_service()
    request_ftp_service()
    request_telnet_service()
    request_dns_service()
    request_smtp_service()
    request_finger_service()