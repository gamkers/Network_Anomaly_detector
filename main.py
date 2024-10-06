from flask import Flask, request, jsonify
import time
from pynotifier import Notification
import requests
from scapy.all import *
import logging
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory storage for IP statistics
ip_stats = defaultdict(lambda: {'count': 0, 'last_seen': 0})

def get_ip_location(ip_address):
    try:
        response = requests.get(f'http://ipinfo.io/{ip_address}/json', timeout=5)
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
        logger.error(f"Error fetching IP location: {e}")
        return None

def check_anomaly(ip_address, location):
    current_time = time.time()
    ip_stats[ip_address]['count'] += 1
    ip_stats[ip_address]['last_seen'] = current_time

    # Anomaly conditions
    is_anomaly = False
    reasons = []

    # Check for high-risk countries (expand this list as needed)
    high_risk_countries = ['CN', 'RU', 'KP','US']
    if location.get('country') in high_risk_countries:
        is_anomaly = True
        reasons.append(f"High-risk country: {location.get('country')}")

    # Check for unusual access patterns
    if ip_stats[ip_address]['count'] > 10 and (current_time - ip_stats[ip_address]['last_seen']) < 60:
        is_anomaly = True
        reasons.append("Unusual access pattern detected")

    # Add more anomaly checks here (e.g., known malicious IP ranges, time-based rules)

    return is_anomaly, reasons

@app.route('/data', methods=['POST'])
def receive_data():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    source_ip = data.get('last_source_ip')
    destination_ip = data.get('last_destination_ip')

    logger.info(f"Received data - Source IP: {source_ip}, Destination IP: {destination_ip}")

    try:
        source_location = get_ip_location(source_ip)
        destination_location = get_ip_location(destination_ip)

        # if source_location:
        #     logger.info(f"Source IP Location: {source_location}")
        # if destination_location:
        #     logger.info(f"Destination IP Location: {destination_location}")

        # Check for anomalies
        source_anomaly, source_reasons = check_anomaly(source_ip, source_location)
        dest_anomaly, dest_reasons = check_anomaly(destination_ip, destination_location)

        if source_anomaly or dest_anomaly:
            anomaly_description = "Anomalies detected:\n"
            if source_anomaly:
                anomaly_description += f"Source IP ({source_ip}): {', '.join(source_reasons)}\n"
            if dest_anomaly:
                anomaly_description += f"Destination IP ({destination_ip}): {', '.join(dest_reasons)}"

            logger.warning(anomaly_description)
            Notification(
                title="ANOMALY DETECTED",
                description=anomaly_description,
                duration=5,
                urgency='critical'
            ).send()

        return jsonify({"message": "Data processed successfully"}), 200

    except Exception as e:
        logger.error(f"Error processing data: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
