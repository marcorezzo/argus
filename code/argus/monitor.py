from datetime import datetime
from elasticsearch import Elasticsearch, exceptions
from elasticsearch.helpers import scan
from brute_force import detect_brute_force
from port_scanning import detect_port_scanning
from traffic_spikes import detect_traffic_spikes
from exploitation import detect_exploitation
from suspicious_transfers import detect_suspicious_transfers
import configparser
import requests
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load configuration
config = configparser.ConfigParser()
config.read('argus.conf')

# Email configuration
email_config = config['email']
SMTP_SERVER = email_config['smtp_server']
SMTP_PORT = email_config['smtp_port']
SMTP_USERNAME = email_config['smtp_username']
SMTP_PASSWORD = email_config['smtp_password']
ALERT_RECIPIENT = email_config['alert_recipient']

# Elasticsearch configuration
es_config = config['elasticsearch']
mapping_file = "argus_mapping.json"

# FreeIPAPI base URL
FREEIPAPI_BASE_URL = 'https://freeipapi.com/api/json/'

def send_alert_email(subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = ALERT_RECIPIENT
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, ALERT_RECIPIENT, text)
        server.quit()
        print("Alert email sent successfully.")
    except Exception as e:
        print(f"Failed to send alert email: {e}")

def get_ip_geolocation(ip=None):
    if ip:
        url = f'{FREEIPAPI_BASE_URL}{ip}'
    else:
        url = FREEIPAPI_BASE_URL  # This will return geolocation of the request sender
    
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "city": data.get('city'),
            "region": data.get('region'),
            "country": data.get('country_name'),
            "latitude": data.get('latitude'),
            "longitude": data.get('longitude')
        }
    else:
        print(f"Failed to retrieve geolocation data for IP: {ip}")
        return None

def enrich_ip_with_geolocation(attempts):
    for ip, details in attempts.items():
        geolocation = get_ip_geolocation(ip)
        if geolocation:
            details['geolocation'] = geolocation

def create_index_with_mapping(es, index_name):
    # Create the index with the specified mapping
    with open(mapping_file, "r") as f:
        mapping = json.load(f)
    
    try:
        if not es.indices.exists(index=index_name):            
            # Create the index with the specified mapping
            es.indices.create(index=index_name, body=mapping)
            print(f"Index '{index_name}' created with custom mapping.")
    except exceptions.RequestError as e:
        print(f"Failed to create index '{index_name}': {e}")

def monitor_activity():
    # Elasticsearch connection
    es = Elasticsearch(
        hosts=[{"host": es_config["host"], "port": int(es_config["port"]), "scheme": es_config["scheme"]}],
        basic_auth=(es_config["username"], es_config["password"]) if es_config["username"] else None,
    )

    # Create the new index with the specified mapping
    create_index_with_mapping(es, es_config["output_index"])

    # Call detection functions
    brute_force_attempts = detect_brute_force(es, es_config["input_index"])
    port_scanning_attempts = detect_port_scanning(es, es_config["input_index"])
    traffic_spikes_data = detect_traffic_spikes(es, es_config["input_index"])
    suspicious_transfers_data = detect_suspicious_transfers(es, es_config["input_index"])
    exploitation_attempts = detect_exploitation(es, es_config["input_index"])

    # Enrich brute force attempts with geolocation data
    enrich_ip_with_geolocation(brute_force_attempts)

    # Prepare the document to index
    doc = {
        "@timestamp": datetime.utcnow(),  # Use @timestamp for time-based visualization in Kibana
        "brute_force_attempts": [
            {
                "ip_address": ip,
                "blacklisted": details.get("blacklisted"),
                "ftp_failed_logins": details.get("ftp_failed_logins"),
                "ssh_failed_logins": details.get("ssh_failed_logins"),
                "timestamps": details.get("timestamps"),
                "geolocation": {
                    "city": details.get("geolocation", {}).get("city"),
                    "region": details.get("geolocation", {}).get("region"),
                    "country": details.get("geolocation", {}).get("country"),
                    "location": {
                        "lat": details.get("geolocation", {}).get("latitude"),
                        "lon": details.get("geolocation", {}).get("longitude")
                    }
                }
            }
            for ip, details in brute_force_attempts.items()
        ],
        "port_scanning_attempts": [
            {
                "ip_address": ip,
                "ports": list(data["ports"]),
                "first_seen": data["first_seen"].isoformat(),
                "last_seen": data["last_seen"].isoformat()
            }
            for ip, data in port_scanning_attempts.items()
        ],
        "traffic_spikes": traffic_spikes_data,  # Traffic spike information
        "suspicious_transfers": suspicious_transfers_data,  # Suspicious transfer information
        "exploitation_attempts": [
            {
                "ip_address": ip,
                "count": count
            }
            for ip, count in exploitation_attempts.items()
        ]  # Exploitation attempt information
    }

    # Index the document into Elasticsearch
    try:
        es.index(index=es_config["output_index"], body=doc)
        print("Monitoring script executed successfully.")
    except Exception as e:
        error_message = f"Failed to index document into Elasticsearch: {e}"
        print(error_message)
        send_alert_email("Elasticsearch Indexing Failed", error_message)

# Execute the monitoring process
if __name__ == "__main__":
    monitor_activity()
