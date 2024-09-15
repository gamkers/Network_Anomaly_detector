from flask import Flask, request, jsonify
import time
from pynotifier import Notification
import requests
from scapy.all import *

def get_ip_location(ip_address):
    try:
        # Make a request to ipinfo.io with the IP address
        response = requests.get(f'http://ipinfo.io/{ip_address}/json')
        response.raise_for_status()  # Raise an error for bad responses
        
        # Convert the response to JSON
        data = response.json()
        
        # Extract location information
        location = {
            'ip': data.get('ip'),
            'hostname': data.get('hostname'),
            'city': data.get('city'),
            'region': data.get('region'),
            'country': data.get('country'),
            'location': data.get('loc'),  # Latitude and Longitude
        }
        
        return location
    
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None

# Example usage
  # Replace with the IP address you want to look up



app = Flask(__name__)

# Route to handle POST requests to /data
@app.route('/data', methods=['POST'])
def receive_data():
    if request.is_json:
        data = request.get_json()
        source_ip = data.get('source_ip')
        destination_ip = data.get('destination_ip')
        packet_data = data.get('packet_data')
        packet_data = packet_data.replace("new ","")
        packet_data = packet_data.replace("Packet Data: ","")
        

        # Show the packet details
        # packet.show()
       
        # print(packet_data)
        # # Log the received data
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")

        if source_ip == "192.168.1.7" and destination_ip == "192.168.1.11":
            log = "DROPPING THE SELF PACKET"
        else:
            integer_list = list(map(int, packet_data.split()))

            # Print the list
            # print(integer_list[14:])

            packet_bytes = bytes(integer_list)
            print(packet_bytes)
    # Parse the packet using scapy
            packet = Ether(packet_bytes)

            # Function to determine if a packet is HTTP, HTTPS, or generic TCP
            def analyze_packet(packet):
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport

                    # Check if the packet is HTTP
                    if src_port == 80 or dst_port == 80:
                        print("HTTP packet detected!")
                    # Check if the packet is HTTPS
                    elif src_port == 443 or dst_port == 443:
                        print("HTTPS packet detected!")
                    else:
                        print(f"TCP packet detected on port {src_port} -> {dst_port}")
                else:
                    print("This is not a TCP packet")

            # Analyze the packet
            analyze_packet(packet)
            packet.show()
            # source_location = get_ip_location(source_ip)
        #     destination_location = get_ip_location(destination_ip)
        #     print("[*] SOURCE INFORMATION")
        #     print("IP Address Location Information:")
        #     print(f"IP: {source_location.get('ip', 'N/A')}")
        #     print(f"Hostname: {source_location.get('hostname', 'N/A')}")
        #     print(f"City: {source_location.get('city', 'N/A')}")
        #     print(f"Region: {source_location.get('region', 'N/A')}")
        #     print(f"Country: {source_location.get('country', 'N/A')}")
        #     print(f"Location: {source_location.get('location', 'N/A')}")

        #     print("-----------------------------------------------")

        #     print("[*] DESTINATION INFORMATION")

        #     print("IP Address Location Information:")
        #     print(f"IP: {destination_location.get('ip', 'N/A')}")
        #     print(f"Hostname: {destination_location.get('hostname', 'N/A')}")
        #     print(f"City: {destination_location.get('city', 'N/A')}")
        #     print(f"Region: {destination_location.get('region', 'N/A')}")
        #     print(f"Country: {destination_location.get('country', 'N/A')}")
        #     print(f"Location: {destination_location.get('location', 'N/A')}")   

        #     print("-----------------------------------------------")

        #     if str({destination_location.get('country', 'N/A')}) == "{'US'}":
                
        #         Notification(
        #             title="ANOMALY DETECTED",
        #             description=f"IP Address Location Information: IP: {destination_location.get('ip', 'N/A')}, Hostname: {destination_location.get('hostname', 'N/A')} Location: {destination_location.get('location', 'N/A')}" ,
        #             duration=5,
        #             urgency='normal'
        #         ).send()


        #     time.sleep(4000)



        # Optionally, you could save the data to a file or database here

        return jsonify({"message": "Data received successfully"}), 200
    
    else:
        return jsonify({"error": "Request must be JSON"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
