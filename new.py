from flask import Flask, request, jsonify,render_template
from pynotifier import Notification
import requests
from collections import defaultdict
import time

app = Flask(__name__)

# In-memory storage for basic traffic statistics
traffic_stats = defaultdict(lambda: {'packet_count': 0, 'total_size': 0, 'last_seen': 0})
port_scan_threshold = 10  # Number of unique ports in a short time to consider as potential port scan
ddos_threshold = 100  # Number of packets from same source in a short time to consider as potential DDoS
connections = []
def get_ip_location(ip_address):
    try:
        response = requests.get(f'http://ipinfo.io/{ip_address}/json')
        response.raise_for_status()
        data = response.json()
        return {
            'ip': data.get('ip'),
            'hostname': data.get('hostname'),
            'city': data.get('city'),
            'region': data.get('region'),
            'country': data.get('country'),
            'location': data.get('loc'),
        }
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None

def detect_anomalies(data):
    anomalies = []
    current_time = time.time()
    
    # Update traffic statistics
    source_ip = data['source_ip']
    traffic_stats[source_ip]['packet_count'] += 1
    traffic_stats[source_ip]['total_size'] += data['packet_size']
    traffic_stats[source_ip]['last_seen'] = current_time
    
    # Check for potential port scan
    if 'ports' not in traffic_stats[source_ip]:
        traffic_stats[source_ip]['ports'] = set()
    traffic_stats[source_ip]['ports'].add(data['destination_port'])
    if len(traffic_stats[source_ip]['ports']) > port_scan_threshold:
        anomalies.append(f"Potential port scan detected from {source_ip}")
    
    # Check for potential DDoS
    if traffic_stats[source_ip]['packet_count'] > ddos_threshold:
        anomalies.append(f"Potential DDoS attack detected from {source_ip}")
    
    # Check for unusual protocols
    # if data['protocol'] not in [6, 17]:  # Not TCP or UDP
    #     anomalies.append(f"Unusual protocol ({data['protocol']}) detected from {source_ip}")
    
    # Check for sensitive ports
    sensitive_ports = [22, 3389]  # SSH and RDP
    if data['destination_port'] in sensitive_ports:
        anomalies.append(f"Access attempt to sensitive port {data['destination_port']} from {source_ip}")
    
    return anomalies

@app.route('/data', methods=['POST'])
def receive_data():
    if request.is_json:
        data = request.get_json()
        
        anomalies = detect_anomalies(data)
        source_location = get_ip_location(data['source_ip'])
        destination_location = get_ip_location(data['destination_ip'])

        if source_location and destination_location:
            connections.append({
                'source': source_location,
                'destination': destination_location,
                'timestamp': time.time()
            })
            
        print("[*] SOURCE INFORMATION")
        print_location_info(source_location)
        print("[*] DESTINATION INFORMATION")
        print_location_info(destination_location)
        
        if anomalies:
            source_location = get_ip_location(data['source_ip'])
            destination_location = get_ip_location(data['destination_ip'])
            
            print("[*] ANOMALY DETECTED")
            for anomaly in anomalies:
                print(anomaly)
            print("[*] SOURCE INFORMATION")
            print_location_info(source_location)
            print("[*] DESTINATION INFORMATION")
            print_location_info(destination_location)
            
            send_notification(anomalies, source_location, destination_location)
        
        return jsonify({"message": "Data processed", "anomalies": anomalies}), 200
    else:
        return jsonify({"error": "Request must be JSON"}), 400

def print_location_info(location):
    if location:
        print("IP Address Location Information:")
        print(f"IP: {location.get('ip', 'N/A')}")
        print(f"Hostname: {location.get('hostname', 'N/A')}")
        print(f"City: {location.get('city', 'N/A')}")
        print(f"Region: {location.get('region', 'N/A')}")
        print(f"Country: {location.get('country', 'N/A')}")
        print(f"Location: {location.get('location', 'N/A')}")
        print("-----------------------------------------------")

def send_notification(anomalies, source_location, destination_location):
    anomaly_str = "\n".join(anomalies)
    Notification(
        title="NETWORK ANOMALY DETECTED",
        description=f"Anomalies:\n{anomaly_str}\n\nSource: {source_location.get('ip', 'N/A')} ({source_location.get('country', 'N/A')})\nDestination: {destination_location.get('ip', 'N/A')} ({destination_location.get('country', 'N/A')})",
        duration=10,
        urgency='critical'
    ).send()
@app.route('/connections')
def get_connections():
    return jsonify(connections)

# New: Add a route to serve the map page
@app.route('/map')
def map_page():
    return render_template('map.html')   

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)