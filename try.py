from flask import Flask, request, jsonify
import time
from pynotifier import Notification
import requests
from scapy.all import *

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

def analyze_packet(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        if src_port == 80 or dst_port == 80:
            return "HTTP"
        elif src_port == 443 or dst_port == 443:
            return "HTTPS"
        else:
            return f"TCP (port {src_port} -> {dst_port})"
    return None

app = Flask(__name__)

@app.route('/data', methods=['POST'])
def receive_data():
    if request.is_json:
        data = request.get_json()
        source_ip = data.get('source_ip')
        destination_ip = data.get('destination_ip')
        packet_data = data.get('packet_data')

        if source_ip == "192.168.1.7" and destination_ip == "192.168.1.11":
            return jsonify({"message": "DROPPING THE SELF PACKET"}), 200

        try:
            # Convert the packet data string to a list of integers
            integer_list = list(map(int, packet_data.split()))
            # Convert the list of integers to bytes
            packet_bytes = bytes(integer_list)
            # Parse the packet using scapy
            packet = Ether(packet_bytes)

            packet_type = analyze_packet(packet)
            if packet_type:
                print(f"{packet_type} packet detected!")

                source_location = get_ip_location(source_ip)
                destination_location = get_ip_location(destination_ip)

                print("[*] SOURCE INFORMATION")
                print_location_info(source_location)

                print("[*] DESTINATION INFORMATION")
                print_location_info(destination_location)

                if destination_location and destination_location.get('country') == 'US':
                    send_notification(destination_location)

                return jsonify({
                    "message": "Data received and analyzed successfully",
                    "packet_type": packet_type,
                    "source_location": source_location,
                    "destination_location": destination_location
                }), 200
            else:
                return jsonify({"message": "Non-TCP packet received"}), 200
        except Exception as e:
            print(f"Error processing packet: {e}")
            return jsonify({"error": f"Error processing packet: {str(e)}"}), 400
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

def send_notification(location):
    Notification(
        title="ANOMALY DETECTED",
        description=f"IP: {location.get('ip', 'N/A')}, Hostname: {location.get('hostname', 'N/A')}, Location: {location.get('location', 'N/A')}",
        duration=5,
        urgency='normal'
    ).send()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)