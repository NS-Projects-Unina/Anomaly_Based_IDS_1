from flask import Flask, jsonify, render_template_string
import socket
import threading
import time
import subprocess
from scapy.all import IP, UDP, TCP, Raw, sniff
import joblib
import pandas as pd

app = Flask(__name__)
received_packets = []
blocked_ips = set()
packet_count = {}

# Load the trained model
model = joblib.load('modello_addestrato.joblib')

def clear_iptables_rules():
    subprocess.run(["iptables", "-F"])
    subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"])
    subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"])
    subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"])

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
        11211: "memcached"
    }
    return services.get(port, "unknown")

def calculate_wrong_fragments(ip_packet):
    wrong_fragments = 0
    if IP in ip_packet:
        ip_layer = ip_packet[IP]
        if ip_layer.frag > 0 and (ip_layer.flags & 0x1) == 0:
            # Questo è un frammento e non l'ultimo frammento
            wrong_fragments += 1
    return wrong_fragments

def extract_packet_info(ip_packet, transport_packet):
    message = ''
    if transport_packet.haslayer(UDP):
        message = bytes(transport_packet[UDP].payload).decode(errors='ignore')
    elif transport_packet.haslayer(TCP):
        message = bytes(transport_packet[TCP].payload).decode(errors='ignore')
    
    duration = 0  # Placeholder, needs actual calculation
    protocol_type = transport_packet.name
    service = get_service(transport_packet.dport)
    flag = "SF"  # Placeholder, needs actual determination
    src_bytes = len(bytes(transport_packet.payload))
    dst_bytes = 0  # Placeholder, needs actual determination
    land = 1 if ip_packet.src == ip_packet.dst else 0
    wrong_fragment = calculate_wrong_fragments(ip_packet)
    urgent = 0
    hot = 0  # Placeholder, needs actual determination
    num_failed_logins = 0  # Placeholder, needs actual determination
    logged_in = 0  # Placeholder, needs actual determination
    num_compromised = 0  # Placeholder, needs actual determination
    root_shell = 0  # Placeholder, needs actual determination
    su_attempted = 0  # Placeholder, needs actual determination
    num_root = 0  # Placeholder, needs actual determination
    num_file_creations = 0  # Placeholder, needs actual determination
    num_shells = 0  # Placeholder, needs actual determination
    num_access_files = 0  # Placeholder, needs actual determination
    num_outbound_cmds = 0  # Placeholder, needs actual determination
    is_host_login = 0  # Placeholder, needs actual determination
    is_guest_login = 0  # Placeholder, needs actual determination
    count = len([pkt for pkt in received_packets if pkt['from_ip'] == ip_packet.src])
    srv_count = len([pkt for pkt in received_packets if pkt['to_ip'] == ip_packet.dst])
    serror_rate = sum(1 for pkt in received_packets if pkt['from_ip'] == ip_packet.src and pkt['flag'] == 'S0') / count if count > 0 else 0
    srv_serror_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['flag'] == 'S0') / srv_count if srv_count > 0 else 0
    rerror_rate = sum(1 for pkt in received_packets if pkt['from_ip'] == ip_packet.src and pkt['flag'] == 'REJ') / count if count > 0 else 0
    srv_rerror_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['flag'] == 'REJ') / srv_count if srv_count > 0 else 0
    same_srv_rate = sum(1 for pkt in received_packets if pkt['from_ip'] == ip_packet.src and pkt['to_port'] == transport_packet.dport) / count if count > 0 else 0
    diff_srv_rate = sum(1 for pkt in received_packets if pkt['from_ip'] == ip_packet.src and pkt['to_port'] != transport_packet.dport) / count if count > 0 else 0
    srv_diff_host_rate = sum(1 for pkt in received_packets if pkt['to_ip'] != ip_packet.dst and pkt['to_port'] == transport_packet.dport) / srv_count if srv_count > 0 else 0
    dst_host_count = len([pkt for pkt in received_packets if pkt['to_ip'] == ip_packet.dst])
    dst_host_srv_count = len([pkt for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['to_port'] == transport_packet.dport])
    dst_host_same_srv_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['to_port'] == transport_packet.dport) / dst_host_count if dst_host_count > 0 else 0
    dst_host_diff_srv_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['to_port'] != transport_packet.dport) / dst_host_count if dst_host_count > 0 else 0
    dst_host_same_src_port_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['from_port'] == transport_packet.sport) / dst_host_count if dst_host_count > 0 else 0
    dst_host_srv_diff_host_rate = sum(1 for pkt in received_packets if pkt['to_ip'] != ip_packet.dst and pkt['to_port'] == transport_packet.dport) / dst_host_srv_count if dst_host_srv_count > 0 else 0
    dst_host_serror_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['flag'] == 'S0') / dst_host_count if dst_host_count > 0 else 0
    dst_host_srv_serror_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['to_port'] == transport_packet.dport and pkt['flag'] == 'S0') / dst_host_srv_count if dst_host_srv_count > 0 else 0
    dst_host_rerror_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['flag'] == 'REJ') / dst_host_count if dst_host_count > 0 else 0
    dst_host_srv_rerror_rate = sum(1 for pkt in received_packets if pkt['to_ip'] == ip_packet.dst and pkt['to_port'] == transport_packet.dport and pkt['flag'] == 'REJ') / dst_host_srv_count if dst_host_srv_count > 0 else 0

    packet_info = {
        "message": message,
        "from_ip": ip_packet.src,
        "from_port": transport_packet.sport,
        "to_ip": ip_packet.dst,
        "to_port": transport_packet.dport,
        "length": len(bytes(ip_packet)),
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        "ip_header": ip_packet.show(dump=True),
        "transport_header": transport_packet.show(dump=True),
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": land,
        "wrong_fragment": wrong_fragment,
        "urgent": urgent,
        "hot": hot,
        "num_failed_logins": num_failed_logins,
        "logged_in": logged_in,
        "num_compromised": num_compromised,
        "root_shell": root_shell,
        "su_attempted": su_attempted,
        "num_root": num_root,
        "num_file_creations": num_file_creations,
        "num_shells": num_shells,
        "num_access_files": num_access_files,
        "num_outbound_cmds": num_outbound_cmds,
        "is_host_login": is_host_login,
        "is_guest_login": is_guest_login,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate
    }

    # Prepare data for prediction
    features = pd.DataFrame([packet_info])
    columns_to_drop = ['message', 'timestamp']
    if 'ip_header' in features.columns:
        columns_to_drop.append('ip_header')
    if 'transport_header' in features.columns:
        columns_to_drop.append('transport_header')
    features = features.drop(columns_to_drop, axis=1)

    # Apply one-hot encoding to categorical features
    features = pd.get_dummies(features)

    # Ensure all expected columns are present
    expected_columns = model.feature_names_in_
    for col in expected_columns:
        if col not in features.columns:
            features[col] = 0

    # Predict the class
    prediction = model.predict(features[expected_columns])[0]
    packet_info['prediction'] = prediction

    return packet_info


def monitor_traffic():
    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info = extract_packet_info(ip_layer, tcp_layer)
                if packet_info["to_port"] != 5000 and packet_info["from_port"]!= 5000 and packet_info["from_ip"] != "172.18.0.4":
                    print(f"Received TCP: {packet_info}")
                    received_packets.append(packet_info)
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info = extract_packet_info(ip_layer, udp_layer)
                print(f"Received UDP: {packet_info}")
                received_packets.append(packet_info)

    sniff(prn=packet_callback, store=0)



def block_ip(ip):
    if ip not in blocked_ips:
        update_iptables_rules(ip)
        blocked_ips.add(ip)
        print(f"Blocked IP: {ip}")

def update_iptables_rules(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

@app.route('/packets', methods=['GET'])
def get_packets():
    return jsonify(received_packets)

@app.route('/blocked_ips', methods=['GET'])
def get_blocked_ips():
    return jsonify(list(blocked_ips))


# FINGER SERVER
def handle_client(client_socket):
    request = client_socket.recv(1024)
    response = "User information not available.\n"
    client_socket.send(response.encode())
    client_socket.close()

def start_finger_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 79))
    server.listen(5)
    print("Finger server listening on port 79")
    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


def start_services():
    subprocess.run(["service", "apache2", "start"])
    subprocess.run(["service", "ssh", "start"])
    subprocess.run(["service", "vsftpd", "start"])
    subprocess.run(["service", "openbsd-inetd", "start"])
    subprocess.run(["service", "named", "start"])
    subprocess.run(["service", "postfix", "start"])
    threading.Thread(target=start_finger_server, daemon=True).start()


@app.route('/')
def index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Network Packet Viewer</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
        <style>
            body {
                background-color: #f4f7f6;
            }
            .table-hover tr:hover {
                background-color: #e6f3ff;
                transition: background-color 0.3s ease;
            }
            pre {
                max-height: 100px;
                overflow-y: auto;
                font-size: 0.75rem;
            }
            .container {
                display: flex;
            }
            .left-column {
                flex: 1;
                margin-right: 1rem;
            }
            .right-column {
                flex: 2;
            }
        </style>
        <script>
            function fetchPackets() {
                fetch('/packets')
                    .then(response => response.json())
                    .then(data => {
                        const tableBody = document.getElementById('packets-table-body');
                        tableBody.innerHTML = '';
                        data.forEach(packet => {
                            const row = document.createElement('tr');
                            row.className = packet.prediction === 'anomaly' ? 'anomaly' : 'normal';
                            row.innerHTML = `
                                <td class="px-4 py-4 whitespace-nowrap">${packet.timestamp}</td>
                                <td class="px-4 py-4 whitespace-nowrap">${packet.from_ip}</td>
                                <td class="px-4 py-4 whitespace-nowrap" style="color: blue;">${packet.from_port}</td>
                                <td class="px-4 py-4 whitespace-nowrap">${packet.to_ip}</td>
                                <td class="px-4 py-4 whitespace-nowrap" style="color: blue;">${packet.to_port}</td>
                                <td class="px-4 py-4 whitespace-nowrap">${packet.protocol_type}</td>
                                <td class="px-4 py-4">${packet.service}</td>
                                <td class="px-4 py-4 whitespace-nowrap" style="color: red;">${packet.prediction}</td>
                                <td class="px-4 py-4"><pre class="bg-gray-50 p-2 rounded">${packet.ip_header}</pre></td>
                                <td class="px-4 py-4"><pre class="bg-gray-50 p-2 rounded">${packet.transport_header}</pre></td>
                            `;
                            tableBody.appendChild(row);
                        });
                    });
            }

            function fetchBlockedIPs() {
                fetch('/blocked_ips')
                    .then(response => response.json())
                    .then(data => {
                        const blockedIPsList = document.getElementById('blocked-ips-list');
                        blockedIPsList.innerHTML = '';
                        data.forEach(ip => {
                            const listItem = document.createElement('li');
                            listItem.textContent = ip;
                            blockedIPsList.appendChild(listItem);
                        });
                    });
            }

            setInterval(fetchPackets, 5000);  // Fetch packets every 5 seconds
            setInterval(fetchBlockedIPs, 5000);  // Fetch blocked IPs every 5 seconds
        </script>
    </head>
    <body class="p-8" onload="fetchPackets(); fetchBlockedIPs();">
        <div class="container mx-auto bg-white shadow-lg rounded-lg overflow-hidden">
            <div class="left-column bg-red-600 text-white p-4">
                <h1 class="text-2xl font-bold">Blocked IPs</h1>
                <ul id="blocked-ips-list" class="list-disc p-4 bg-white text-black rounded-lg">
                </ul>
            </div>
            <div class="right-column">
                <div class="bg-blue-600 text-white p-4">
                    <h1 class="text-2xl font-bold">Received Network Packets</h1>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full table-hover">
                        <thead class="bg-gray-100">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">From IP</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">From Port</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">To IP</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">To Port</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol Type</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Prediction</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Header</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Transport Header</th>
                            </tr>
                        </thead>
                        <tbody id="packets-table-body" class="bg-white divide-y divide-gray-200">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)


if __name__ == "__main__":
    clear_iptables_rules()
    start_services()
    threading.Thread(target=monitor_traffic, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
