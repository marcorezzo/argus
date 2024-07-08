from flask import Flask, render_template, request, redirect
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import re
import json
import os
import requests

app = Flask(__name__)

# Configuration
CONFIG = {
    "es_host": "172.19.0.2",
    "es_port": 9200,
    "es_username": "elastic",
    "es_password": "argusIsTheBest123",
    "es_index": "filebeat-*",
    "shared_folder": "/shared/abuseipdb",
    "blacklist_filename": "blacklist.json",
    "abuseipdb_api_key": "daf0e987087a869b8022a2c3e5f0f28a3afaf0ae6c9c24ac60ac9de09d25b27e4c763cedc06e9e1d",
    "threshold_seconds": 600  # Adjust threshold as needed
}

# Elasticsearch connection
es = Elasticsearch(
    hosts=[{"host": CONFIG["es_host"], "port": CONFIG["es_port"], "scheme": "http"}],
    basic_auth=(CONFIG["es_username"], CONFIG["es_password"]) if CONFIG["es_username"] else None,
)

# Load blacklist
blacklist_path = os.path.join(CONFIG["shared_folder"], CONFIG["blacklist_filename"])
blacklist_ips = set()

if os.path.exists(blacklist_path):
    with open(blacklist_path, 'r') as file:
        blacklist_data = json.load(file)
        blacklist_ips = {entry['ipAddress'] for entry in blacklist_data['data']}
else:
    print(f"Blacklist file {blacklist_path} not found.")

# Helper function to check for rapid login attempts
def is_rapid_attempt(timestamps):
    timestamps.sort()
    for i in range(1, len(timestamps)):
        if (timestamps[i] - timestamps[i-1]).total_seconds() <= CONFIG["threshold_seconds"]:
            return True
    return False

# Routes
@app.route('/')
def index():
    now = datetime.now()
    two_hours_ago = now - timedelta(hours=2)

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": two_hours_ago, "lte": now}}},
                    {"terms": {"log.file.path": ["/var/log/auth.log", "/var/log/vsftpd.log"]}}
                ],
                "should": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"match_phrase": {"message": "FAIL LOGIN"}}
                ]
            }
        }
    }

    suspicious_ips = {}
    for hit in scan(es, index=CONFIG["es_index"], query=query, scroll='2m', size=100):
        message = hit['_source']['message']
        timestamp = datetime.strptime(hit['_source']['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')

        ip_match = re.search(r"(\d{1,3}\.){3}\d{1,3}", message)
        if ip_match:
            ip_address = ip_match.group(0)
            if ip_address not in suspicious_ips:
                suspicious_ips[ip_address] = {"count": 0, "last_attempt": timestamp}
            suspicious_ips[ip_address]["count"] += 1
            if timestamp > suspicious_ips[ip_address]["last_attempt"]:
                suspicious_ips[ip_address]["last_attempt"] = timestamp

    return render_template('index.html', suspicious_ips=suspicious_ips)

@app.route('/report', methods=['POST'])
def report():
    ip_address = request.form['ip_address']
    report_payload = {
        "ip": ip_address,
        "categories": "18,22",
        "comment": "Reported by your_app_name",
        "key": CONFIG["abuseipdb_api_key"]
    }
    response = requests.post("https://api.abuseipdb.com/api/v2/report", data=report_payload)
    if response.status_code == 200:
        print(f"Reported IP {ip_address} to AbuseIPDB.")
        return redirect('/')
    else:
        print(f"Failed to report IP {ip_address} to AbuseIPDB.")
        return "Failed to report the IP address to AbuseIPDB.", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
