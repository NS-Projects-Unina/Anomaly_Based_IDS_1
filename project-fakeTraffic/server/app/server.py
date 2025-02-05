import hashlib
from flask import Flask, jsonify, render_template_string, send_from_directory
import socket
import threading
import time
from datetime import datetime, timedelta
import subprocess
from scapy.all import IP, UDP, TCP, Raw, sniff
import joblib
import pandas as pd
from collections import defaultdict

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
        11211: "memcached",
        65432: "private",
        65433: "private"
    }
    return services.get(port, "other")


# Tabella globale dei flussi attivi (flow_id -> dettagli flusso)
flow_table = defaultdict(lambda: {"packet_count": 0, "byte_count": 0, "last_seen": None})


def extract_packet_info(ip_packet, transport_packet, proto):
    try:
        service = get_service(transport_packet.dport)
        protocol = 17 if UDP in transport_packet else 6 if TCP in transport_packet else 0
        flow_data = f"{ip_packet.src}-{transport_packet.sport}-{ip_packet.dst}-{transport_packet.dport}-{protocol}"
        flow_id = int(hashlib.sha1(flow_data.encode()).hexdigest(), 16) % (10**9)
        protocol_map = proto
        l4_src_port = transport_packet.sport
        ipv4_src_addr = ip_packet.src
        l4_dst_port = transport_packet.dport
        ipv4_dst_addr = ip_packet.dst
        tcp_flags = int(transport_packet.flags) if TCP in transport_packet else 0
        tcp_win_mss_in = getattr(transport_packet, 'mss', 0)
        tcp_win_scale_in = getattr(transport_packet, 'window_scale', 0)
        tcp_win_scale_out = getattr(transport_packet, 'window_scale', 0)
        tcp_win_max_in = (transport_packet.window * 2**tcp_win_scale_in) if TCP in transport_packet else 0
        tcp_win_max_out = (transport_packet.window * 2**tcp_win_scale_out) if TCP in transport_packet else 0
        tcp_win_min_in = (transport_packet.window * 2**tcp_win_scale_in) if TCP in transport_packet else 0
        tcp_win_min_out = (transport_packet.window * 2**tcp_win_scale_out) if TCP in transport_packet else 0
        src_tos = ip_packet.tos
        dst_tos = 0  # Placeholder, needs actual determination
        # Recupera il flusso esistente o inizializza uno nuovo
        current_time = datetime.now()
        flow = flow_table[flow_id]
        flow["packet_count"] += 1
        flow["byte_count"] += len(ip_packet)
        flow["last_seen"] = current_time
        total_flows_exp = 0
        timeout_inactive = timedelta(seconds=15)  # Esporta flusso se inattivo per 15s
        if flow["last_seen"] and (current_time - flow["last_seen"]) > timeout_inactive:
            total_flows_exp += 1
            del flow_table[flow_id]  # Rimuove il flusso esportato
        min_ip_pkt_len = len(ip_packet)  # Placeholder, needs actual determination
        max_ip_pkt_len = len(ip_packet)  # Placeholder, needs actual determination
        total_pkts_exp = flow["packet_count"]
        total_bytes_exp = flow["byte_count"]
        in_bytes = len(bytes(ip_packet))
        in_pkts = 1
        out_bytes = 0
        out_pkts = 0
        analysis_timestamp = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        anomaly = "None"  # predetto dopo

        packet_info = {
            "SERVICE": service,
            "FLOW_ID": flow_id,
            "PROTOCOL_MAP": protocol_map,
            "L4_SRC_PORT": l4_src_port,
            "IPV4_SRC_ADDR": ipv4_src_addr,
            "L4_DST_PORT": l4_dst_port,
            "IPV4_DST_ADDR": ipv4_dst_addr,
            "TCP_FLAGS": tcp_flags,
            "TCP_WIN_MAX_IN": tcp_win_max_in,
            "TCP_WIN_MAX_OUT": tcp_win_max_out,
            "TCP_WIN_MIN_IN": tcp_win_min_in,
            "TCP_WIN_MIN_OUT": tcp_win_min_out,
            "TCP_WIN_MSS_IN": tcp_win_mss_in,
            "TCP_WIN_SCALE_IN": tcp_win_scale_in,
            "TCP_WIN_SCALE_OUT": tcp_win_scale_out,
            "SRC_TOS": src_tos,
            "DST_TOS": dst_tos,
            "TOTAL_FLOWS_EXP": total_flows_exp,
            "MIN_IP_PKT_LEN": min_ip_pkt_len,
            "MAX_IP_PKT_LEN": max_ip_pkt_len,
            "TOTAL_PKTS_EXP": total_pkts_exp,
            "TOTAL_BYTES_EXP": total_bytes_exp,
            "IN_BYTES": in_bytes,
            "IN_PKTS": in_pkts,
            "OUT_BYTES": out_bytes,
            "OUT_PKTS": out_pkts,
            "ANALYSIS_TIMESTAMP": analysis_timestamp,
            "ANOMALY": anomaly
        }

        # Prepare data for prediction
        features = pd.DataFrame([packet_info])
        features = pd.get_dummies(features)

        # Ensure all expected columns are present
        expected_columns = model.feature_names_in_
        for col in expected_columns:
            if col not in features.columns:
                features[col] = 0

        # Predict the alert
        prediction = model.predict(features[expected_columns])[0]
        packet_info['ANOMALY'] = prediction

        return packet_info

    except Exception as e:
        print(f"Error extracting packet info: {e}")
        return None


def monitor_traffic():
    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info = extract_packet_info(ip_layer, tcp_layer, "tcp")
                if packet_info and packet_info["L4_DST_PORT"] != 5000 and packet_info["L4_SRC_PORT"] != 5000 and packet_info["IPV4_SRC_ADDR"] != "172.18.0.4":
                    print(f"Received TCP: {packet_info}")
                    received_packets.append(packet_info)
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info = extract_packet_info(ip_layer, udp_layer, "udp")
                if packet_info:
                    print(f"Received UDP: {packet_info}")
                    received_packets.append(packet_info)
        else:
            print(f"Received non-IP packet: {packet.summary()}")

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


@app.route('/packet_statistics')
def packet_statistics():
    udp_count = sum(1 for packet in received_packets if packet["PROTOCOL_MAP"] == "udp")
    tcp_count = sum(1 for packet in received_packets if packet["PROTOCOL_MAP"] == "tcp")
    http_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 80)
    ssh_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 22)
    ftp_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 21)
    telnet_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 23)
    dns_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 53)
    smtp_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 25)
    finger_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] == 79)
    private_count = sum(1 for packet in received_packets if packet["L4_DST_PORT"] in [65432, 65433])

    # Calcolare la porta più utilizzata
    to_port_usage = {}
    for packet in received_packets:
        port = packet["L4_DST_PORT"]
        if port in to_port_usage:
            to_port_usage[port] += 1
        else:
            to_port_usage[port] = 1
    most_used_port = max(to_port_usage, key=to_port_usage.get) if to_port_usage else 0

    stats = {
        "udp_count": udp_count,
        "tcp_count": tcp_count,
        "http_count": http_count,
        "ssh_count": ssh_count,
        "ftp_count": ftp_count,
        "telnet_count": telnet_count,
        "dns_count": dns_count,
        "smtp_count": smtp_count,
        "finger_count": finger_count,
        "private_count": private_count,
        "most_used_port": most_used_port
    }

    return jsonify(stats)


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

def start_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 65433))
    server.listen(5)
    print("TCP server listening on port 65433")
    while True:
        client_socket, addr = server.accept()
        message = client_socket.recv(1024).decode(errors='ignore')
        print(f"Received TCP: {message}")
        client_socket.close()

def start_services():
    subprocess.run(["service", "apache2", "start"])
    subprocess.run(["service", "ssh", "start"])
    subprocess.run(["service", "vsftpd", "start"])
    subprocess.run(["service", "openbsd-inetd", "start"])
    subprocess.run(["service", "named", "start"])
    subprocess.run(["service", "postfix", "start"])
    threading.Thread(target=start_finger_server, daemon=True).start()
    threading.Thread(target=start_tcp_server, daemon=True).start()


@app.route('/')
def index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Monitor</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }

            body {
                background-color: #f0f2f5;
                padding: 20px;
            }

            .dashboard {
                max-width: 1400px;
                margin: 0 auto;
            }

            .stats-container {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 20px;
                margin-bottom: 20px;
            }

            .card {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }

            .chart-container {
                height: 300px;
            }

            .blocked-ips {
                background: white;
                padding: 20px;
                border-radius: 10px;
            }

            .blocked-ips h2 {
                color: #e11d48;
                margin-bottom: 15px;
            }

            .blocked-list {
                max-height: 250px;
                overflow-y: auto;
                background: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
            }

            .blocked-list li {
                padding: 8px;
                border-bottom: 1px solid #e9ecef;
                font-size: 14px;
            }

            .packets-table {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                overflow-x: auto;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th {
                background: #f8f9fa;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #4b5563;
            }

            td {
                padding: 12px;
                border-bottom: 1px solid #e9ecef;
            }

            tr:hover {
                background-color: #f8f9fa;
            }
            
            .protocol-udp {
                color: #b8b800;
                text-shadow: 0 0 10px rgba(255, 255, 0, 0.5);
            }
            .protocol-tcp {
                color: #ff6666;
                text-shadow: 0 0 10px rgba(255, 102, 102, 0.5);
            }

            /* Service Colors with Neon Effect */
            .service-http { 
                color: #60a5fa;
                text-shadow: 0 0 10px rgba(96, 165, 250, 0.5);
            }
            .service-ssh { 
                color: #a78bfa;
                text-shadow: 0 0 10px rgba(167, 139, 250, 0.5);
            }
            .service-ftp { 
                color: #f472b6;
                text-shadow: 0 0 10px rgba(244, 114, 182, 0.5);
            }
            .service-telnet { 
                color: #fb923c;
                text-shadow: 0 0 10px rgba(251, 146, 60, 0.5);
            }
            .service-dns { 
                color: #2dd4bf;
                text-shadow: 0 0 10px rgba(45, 212, 191, 0.5);
            }
            
            .service-smtp { 
                color: #22c55e;
                text-shadow: 0 0 10px rgba(34, 197, 94, 0.5);
            }
            .service-finger { 
                color: #eab308;
                text-shadow: 0 0 10px rgba(234, 179, 8, 0.5);
            }
            .service-private { 
                color: #94a3b8;
                text-shadow: 0 0 10px rgba(148, 163, 184, 0.5);
            }
            
            .status-badge {
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 500;
            }

            .status-normal {
                background-color: #dcfce7;
                color: #166534;
            }

            .status-anomaly {
                background-color: #fee2e2;
                color: #991b1b;
            }

            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }

            .stat-card {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
            }

            .stat-value {
                font-size: 24px;
                font-weight: bold;
                margin: 10px 0;
            }

            .stat-label {
                font-size: 14px;
                color: #6b7280;
            }
            
            .service-cell {
                display: flex;
                align-items: center;
                gap: 8px;
            }

        </style>
    </head>
    <body>
        <div class="dashboard">
            <div class="stats-container">
                <div class="card">
                    <h2>Network Traffic</h2>
                    <div class="chart-container">
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
                <div class="blocked-ips">
                    <h2>⚠️ Blocked IPs</h2>
                    <ul class="blocked-list" id="blocked-ips-list">
                        <!-- Blocked IPs will be populated here -->
                    </ul>
                </div>
            </div>

            <div class="card">
                <h2>📊 Key Metrics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value" id="udp-count">0</div>
                        <div class="stat-label">UDP Packets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="tcp-count">0</div>
                        <div class="stat-label">TCP Packets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="most-used-port">-</div>
                        <div class="stat-label">Most Used Port</div>
                    </div>
                </div>
            </div>

            <div class="packets-table">
                <h2>🔍 Network Packets Analysis</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>From</th>
                            <th>To</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="packets-table-body">
                        <!-- Packet data will be populated here -->
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            let trafficChart;

                // Definiamo i colori base uguali a quelli dei servizi nella tabella
                const serviceColors = {
                    'udp': '#b8b800',      // yellow for UDP
                    'tcp': '#ff6666',      // fuchsia for TCP
                    'http': '#60a5fa',     // blue
                    'ssh': '#a78bfa',      // purple
                    'ftp': '#f472b6',      // pink
                    'telnet': '#fb923c',   // orange
                    'dns': '#2dd4bf',      // teal
                    'smtp': '#22c55e',     // green
                    'finger': '#eab308',   // yellow
                    'private': '#94a3b8'   // gray
                };
                
                function initChart() {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                trafficChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['UDP', 'TCP', 'HTTP', 'SSH', 'FTP', 'Telnet', 'DNS', 'SMTP', 'Finger', 'Private'],
                        datasets: [{
                            label: 'Packet Count',
                            data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            backgroundColor : ['#b8b800', '#ff6666', '#60a5fa', '#a78bfa', '#f472b6', '#fb923c', '#2dd4bf', '#22c55e', '#eab308', '#94a3b8']  
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
            }

        function getServiceClass(service) {
                return service.toLowerCase() in serviceColors 
                    ? `service-${service.toLowerCase()}` 
                    : '';
            }
            
            function getProtocolClass(protocol) {
                return protocol.toLowerCase() === 'udp' || protocol.toLowerCase() === 'tcp'
                    ? `protocol-${protocol.toLowerCase()}`
                    : '';
            }
            
            function updatePacketsTable(packets) {
                const tableBody = document.getElementById('packets-table-body');
                tableBody.innerHTML = '';
                
                packets.forEach(packet => {
                    const row = document.createElement('tr');
                    const service = packet.SERVICE.toLowerCase();
                    const protocol = packet.PROTOCOL_MAP.toLowerCase();
                    const serviceColor = serviceColors[service] || { text: '#000', background: '#f0f0f0' };
                    row.innerHTML = `
                        <td>${packet.ANALYSIS_TIMESTAMP}</td>
                        <td>${packet.IPV4_SRC_ADDR}:${packet.L4_SRC_PORT}</td>
                        <td>${packet.IPV4_DST_ADDR}:${packet.L4_DST_PORT}</td>
                        <td><span class="${getProtocolClass(packet.PROTOCOL_MAP)}">${packet.PROTOCOL_MAP}</span></td>
                        <td>
                            <div class="service-cell">
                                <span class="service-${service}" style="color: ${serviceColor.text}">${packet.SERVICE}</span>
                            </div>
                        </td>
                        <td>${packet.ANOMALY}</td>
                    `;
                    tableBody.appendChild(row);
                });
            }
            
            function updateStatistics(stats) {
                document.getElementById('udp-count').textContent = stats.udp_count;
                document.getElementById('tcp-count').textContent = stats.tcp_count;
                document.getElementById('most-used-port').textContent = stats.most_used_port;

                trafficChart.data.datasets[0].data = [
                    stats.udp_count,
                    stats.tcp_count,
                    stats.http_count,
                    stats.ssh_count,
                    stats.ftp_count,
                    stats.telnet_count,
                    stats.dns_count,
                    stats.smtp_count,
                    stats.finger_count,
                    stats.private_count
                ];
                trafficChart.update();
            }

            function updateBlockedIPs(ips) {
                const list = document.getElementById('blocked-ips-list');
                list.innerHTML = '';
                ips.forEach(ip => {
                    const li = document.createElement('li');
                    li.textContent = ip;
                    list.appendChild(li);
                });
            }

            function fetchData() {
                Promise.all([
                    fetch('/packets').then(res => res.json()),
                    fetch('/blocked_ips').then(res => res.json()),
                    fetch('/packet_statistics').then(res => res.json())
                ]).then(([packets, blockedIPs, stats]) => {
                    updatePacketsTable(packets);
                    updateBlockedIPs(blockedIPs);
                    updateStatistics(stats);
                });
            }

            // Initialize
            initChart();
            fetchData();
            setInterval(fetchData, 5000);
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/<path:filename>')
def serve_html(filename):
    return send_from_directory('/var/www/html', filename)

if __name__ == "__main__":
    clear_iptables_rules()
    start_services()
    threading.Thread(target=monitor_traffic, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
