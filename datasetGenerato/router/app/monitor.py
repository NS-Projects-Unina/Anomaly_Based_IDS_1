import hashlib
from flask import Flask, jsonify, render_template_string
import threading
from datetime import datetime, timedelta
from scapy.all import IP, UDP, TCP, ICMP, sniff
import pandas as pd
from collections import defaultdict
import joblib 
import subprocess
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)
received_packets = []
blocked_ips = set()
packet_count = {}

# Load the trained model
model = joblib.load('modello_addestrato.joblib')

# Tabella globale dei flussi attivi (flow_id -> dettagli flusso)
flow_table = defaultdict(lambda: {"packet_count": 0, "byte_count": 0, "last_seen": None})

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
        packet_info["TIMESTAMP"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
        packet_info["payload_size"] = 0
        packet_info["icmp_type"] = 0
        packet_info["icmp_code"] = 0
        packet_info["service"] = get_service(transport_packet.dport)
            
        
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
        
        packet_info_prediction = packet_info

        # Prepare data for prediction
        # Create dummy columns for the PROTOCOL MAP column
        packet_info_prediction["flags"] = str(packet_info_prediction["flags"])
        flags_dummies = pd.get_dummies(packet_info_prediction['flags'], prefix='flags', drop_first=True)
        

        # Rimuovi le colonne originali e aggiungi le nuove colonne numeriche
        packet_info_prediction = pd.DataFrame(packet_info_prediction, index=[0])
        packet_info_prediction = packet_info_prediction.drop(['flags'], axis=1)  # Rimuove le colonne testuali
        packet_info_prediction = pd.concat([packet_info_prediction, flags_dummies], axis=1)
        
        
        # Ensure all expected columns are present
        expected_columns = model.feature_names_in_
        for col in expected_columns:
            if col not in packet_info_prediction.columns:
                packet_info_prediction[col] = 0

        packet_info_prediction = packet_info_prediction[expected_columns]

        # Scale the data
        fitter = joblib.load('scaler_fitter.joblib')

        packet_info_prediction_scaled = fitter.transform(packet_info_prediction)

        # Convert back to DataFrame to retain column names
        packet_info_prediction_scaled = pd.DataFrame(
            packet_info_prediction_scaled, 
            columns=expected_columns
        )

        # Predict the alert
        prediction = model.predict(packet_info_prediction_scaled)[0]
        packet_info['ANOMALY'] = prediction
        print(packet_info)
        
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
    udp_count = sum(1 for packet in received_packets if packet["protocol"] == "udp")
    tcp_count = sum(1 for packet in received_packets if packet["protocol"] == "tcp")
    icmp_count = sum(1 for packet in received_packets if packet["protocol"] == "icmp")
    http_count = sum(1 for packet in received_packets if packet["dst_port"] == 80)
    ssh_count = sum(1 for packet in received_packets if packet["dst_port"] == 22)
    ftp_count = sum(1 for packet in received_packets if packet["dst_port"] == 21)
    telnet_count = sum(1 for packet in received_packets if packet["dst_port"] == 23)
    dns_count = sum(1 for packet in received_packets if packet["dst_port"] == 53)
    smtp_count = sum(1 for packet in received_packets if packet["dst_port"] == 25)
    finger_count = sum(1 for packet in received_packets if packet["dst_port"] == 79)
    private_count = sum(1 for packet in received_packets if packet["dst_port"] in [65432, 65433])

    # Calcolare la porta più utilizzata
    to_port_usage = {}
    for packet in received_packets:
        port = packet["dst_port"]
        if port in to_port_usage:
            to_port_usage[port] += 1
        else:
            to_port_usage[port] = 1
    most_used_port = max(to_port_usage, key=to_port_usage.get) if to_port_usage else 0

    stats = {
        "udp_count": udp_count,
        "tcp_count": tcp_count,
        "icmp_count": icmp_count,
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
        
            .protocol-icmp {
                color: #5a67d8;
                text-shadow: 0 0 10px rgba(90, 103, 216, 0.5);
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
            
            .service-other {
                color: #000000;
                text-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            }
            
            .status-badge {
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
            }

            .status-anomaly {
                background-color: #fecaca;  /* Light red */
                color: #991b1b;  /* Dark red */
            }
            
            .status-normal {
                background-color: #d1f2d1;
                color: #1a5f1a;
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
                        <div class="stat-value" id="icmp-count">0</div>
                        <div class="stat-label">ICMP Packets</div>
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
                    'icmp': '#5a67d8',     // indigo for ICMP
                    'http': '#60a5fa',     // blue
                    'ssh': '#a78bfa',      // purple
                    'ftp': '#f472b6',      // pink
                    'telnet': '#fb923c',   // orange
                    'dns': '#2dd4bf',      // teal
                    'smtp': '#22c55e',     // green
                    'finger': '#eab308',   // yellow
                    'private': '#94a3b8',  // gray
                    'other' : "#000000"
                };
                
                function initChart() {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                trafficChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['UDP', 'TCP', 'ICMP', 'HTTP', 'SSH', 'FTP', 'Telnet', 'DNS', 'SMTP', 'Finger', 'Private'],
                        datasets: [{
                            label: 'Packet Count',
                            data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            backgroundColor : ['#b8b800', '#ff6666','#5a67d8','#60a5fa', '#a78bfa', '#f472b6', '#fb923c', '#2dd4bf', '#22c55e', '#eab308', '#94a3b8']  
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
                return protocol=== 'udp' || protocol=== 'tcp'
                    ? `protocol-${protocol}`
                    : '';
            }
            
            function getStatusBadge(anomaly) {
                
                if (!anomaly || anomaly.toLowerCase() === 'no alert') {
                    return `<span class="status-badge status-normal">No Alert</span>`;
                }
                
                return `<span class="status-badge status-anomaly">${anomaly}</span>`;
            }
            
            function updatePacketsTable(packets) {
                const tableBody = document.getElementById('packets-table-body');
                tableBody.innerHTML = '';
                
                packets.forEach(packet => {
                    const row = document.createElement('tr');
                    const service = packet.service.toLowerCase();
                    const protocol = packet.protocol;
                    const serviceColor = serviceColors[service] || { text: '#000', background: '#f0f0f0' };
                    row.innerHTML = `
                        <td>${packet.TIMESTAMP}</td>
                        <td>${packet.ip_src}:${packet.src_port}</td>
                        <td>${packet.ip_dst}:${packet.dst_port}</td>
                        <td><span class="${getProtocolClass(packet.protocol)}">${packet.protocol}</span></td>
                        <td>
                            <div class="service-cell">
                                <span class="service-${service}" style="color: ${serviceColor.text}">${packet.service}</span>
                            </div>
                        </td>
                        <td>${getStatusBadge(packet.ANOMALY)}</td>
                    `;
                    tableBody.appendChild(row);
                });
            }
            
            function updateStatistics(stats) {
                document.getElementById('udp-count').textContent = stats.udp_count;
                document.getElementById('tcp-count').textContent = stats.tcp_count;
                document.getElementById('icmp-count').textContent = stats.icmp_count;
                document.getElementById('most-used-port').textContent = stats.most_used_port;

                trafficChart.data.datasets[0].data = [
                    stats.udp_count,
                    stats.tcp_count,
                    stats.icmp_count,
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

if __name__ == "__main__":
    threading.Thread(target=monitor_traffic, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
