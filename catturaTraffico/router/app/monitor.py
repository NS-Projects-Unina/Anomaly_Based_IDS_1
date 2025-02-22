from flask import Flask
import threading
from datetime import datetime, timedelta
from scapy.all import IP, UDP, TCP, ICMP, sniff
import csv
import os


app = Flask(__name__)
received_packets = []


def get_service(port):
    services = {
        80: "http",
        443: "https",
        21: "ftp",
        22: "ssh",
        25: "smtp",
        79: "finger",
        110: "pop3",
        143: "imap",
        53: "dns",
        123: "ntp",
        161: "snmp",
        23: "telnet",
        69: "tftp",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        11211: "memcached",
        65432: "private",
        65433: "private"
    }
    return services.get(port, "other")


def extract_packet_info(ip_packet, transport_packet, proto):
    packet_info = {}

    try:
        # Analisi Livello 3 - IP
        packet_info["ip_src"] = ip_packet.src
        packet_info["ip_dst"] = ip_packet.dst
        packet_info["ttl"] = ip_packet.ttl
        packet_info["ip_len"] = ip_packet.len
        packet_info["fragmentation"] = ip_packet.flags.MF or ip_packet.frag > 0
        packet_info["protocol"] = ip_packet.proto
        packet_info["src_port"] = 0
        packet_info["dst_port"] = 0
        packet_info["flags"] = 0
        packet_info["seq"] = 0
        packet_info["ack"] = 0
        packet_info["window_size"] = 0
        packet_info["urgent"] = 0
        packet_info["src_port"] = 0
        packet_info["dst_port"] = 0
        packet_info["payload_size"] = 0
        packet_info["icmp_type"] = 0
        packet_info["icmp_code"] = 0
            
        
        if proto == "tcp":
            packet_info["src_port"] = transport_packet.sport
            packet_info["dst_port"] = transport_packet.dport
            packet_info["flags"] = transport_packet.flags
            packet_info["seq"] = transport_packet.seq
            packet_info["ack"] = transport_packet.ack
            packet_info["window_size"] = transport_packet.window
            packet_info["urgent"] = transport_packet.urgptr
        
        elif proto == "udp":
            packet_info["src_port"] = transport_packet.sport
            packet_info["dst_port"] = transport_packet.dport
            packet_info["payload_size"] = len(transport_packet.payload)
            
        elif proto == "icmp":
            packet_info["icmp_type"] = transport_packet.type
            packet_info["icmp_code"] = transport_packet.code
        
        save_packet_info_to_csv(packet_info)
        return packet_info
    except Exception as e:
        print(f"Error: {e}")
        return None

def save_packet_info_to_csv(packet_info, filename="/app/data/traffico.csv"):
    """
    Salva le informazioni del pacchetto nel file CSV specificato.
    Usa il percorso /app/data nel container che è bindato alla cartella del computer host.
    """

    # Verifica se il file esiste per decidere se scrivere l'intestazione
    file_exists = os.path.exists(filename)

    # Apre il file in modalità append
    with open(filename, mode='a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=packet_info.keys())
        
        # Se il file non esiste, scrive l'intestazione
        if not file_exists:
            writer.writeheader()
        
        # Scrive i dati del pacchetto
        writer.writerow(packet_info)


def monitor_traffic():
    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info = extract_packet_info(ip_layer, tcp_layer, "tcp")
                if packet_info and packet_info["dst_port"] != 5000 and packet_info["src_port"] != 5000 and packet_info["ip_src"] != "172.18.0.4":
                    print(f"Received TCP: {packet_info}")
                    received_packets.append(packet_info)
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info = extract_packet_info(ip_layer, udp_layer, "udp")
                if packet_info:
                    print(f"Received UDP: {packet_info}")
                    received_packets.append(packet_info)
            else:
                icmp_layer = packet[ICMP]
                packet_info = extract_packet_info(ip_layer, icmp_layer, "icmp")
                if packet_info:
                    print(f"Received ICMP: {packet_info}")
                    received_packets.append(packet_info)
        else:
            print(f"Received non-IP packet: {packet.summary()}")

    sniff(prn=packet_callback, store=0)



if __name__ == "__main__":
    threading.Thread(target=monitor_traffic, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
