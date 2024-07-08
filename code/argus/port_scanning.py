from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import re
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('argus.conf')

# Elasticsearch configuration
ps_config = config['port_scanning']


def detect_port_scanning(es, index):
    # Define the time frame for detection
    now = datetime.now()
    fifteen_minutes_ago = now - timedelta(minutes=int(ps_config["time_window"]))

    # Define the query for detecting port scanning attempts
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": fifteen_minutes_ago, "lte": now}}},
                    {"match_phrase": {"log.file.path": "/var/log/auth.log"}},
                    {"match_phrase": {"message": "Port"}}
                ]
            }
        }
    }

    # Process the results
    port_scanning_attempts = {}
    for hit in scan(es, index=index, query=query, scroll='2m', size=100):
        message = hit['_source']['message']
        timestamp = datetime.strptime(hit['_source']['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')

        ip_match = re.search(r"(\d{1,3}\.){3}\d{1,3}", message)
        if ip_match:
            ip_address = ip_match.group(0)
            port_match = re.search(r"port (\d+)", message)
            if port_match:
                port = port_match.group(1)
                if ip_address not in port_scanning_attempts:
                    port_scanning_attempts[ip_address] = {'ports': set(), 'timestamps': []}
                port_scanning_attempts[ip_address]['ports'].add(port)
                port_scanning_attempts[ip_address]['timestamps'].append(timestamp)

    # Filter out IPs with a high number of distinct ports within the time frame
    suspicious_ips = {}
    for ip, data in port_scanning_attempts.items():
        if len(data['ports']) > 10:  # Threshold for number of ports
            suspicious_ips[ip] = {
                'ports': list(data['ports']),
                'first_seen': min(data['timestamps']),
                'last_seen': max(data['timestamps'])
            }
            print("Port scanning found: ")
            print(ip)
    
    return suspicious_ips
