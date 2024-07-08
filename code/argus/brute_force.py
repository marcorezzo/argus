from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import os
import json
import re
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('argus.conf')

# Elasticsearch configuration
br_config = config['brute_force']

# Load blacklist
blacklist_ips = set()

blacklist_file = br_config['blacklist_filename']

if os.path.exists(blacklist_file):
    with open(blacklist_file, 'r') as file:
        blacklist_data = json.load(file)
        blacklist_ips = {entry['ipAddress'] for entry in blacklist_data['data']}
else:
    print(f"Blacklist file {blacklist_file} not found.")

def detect_brute_force(es, index):
    # Define the query for detecting brute force attacks
    now = datetime.now()
    time_frame = now - timedelta(minutes=int(br_config["time_window"]))

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_frame, "lte": now}}}
                ],
                "should": [
                    {"match_phrase": {"log.file.path": "/var/log/auth.log"}},
                    {"match_phrase": {"message": "Failed password"}}
                ]
            }
        }
    }

    # Define the time window and attempt threshold
    time_window = timedelta(seconds=int(br_config["attempt_timeframe"]))

    # Process the results
    brute_force_attempts = {}

    for hit in scan(es, index=index, query=query, scroll='2m', size=100):
        message = hit['_source']['message']
        timestamp = datetime.strptime(hit['_source']['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')

        ip_match = re.search(r"(\d{1,3}\.){3}\d{1,3}", message)
        if ip_match:
            ip_address = ip_match.group(0)
            if ip_address not in brute_force_attempts:
                brute_force_attempts[ip_address] = {"timestamps": [], "blacklisted": False}

            # Append the current timestamp to the list of timestamps
            brute_force_attempts[ip_address]["timestamps"].append(timestamp)

            # Filter timestamps to keep only those within the last time_window
            recent_attempts = [ts for ts in brute_force_attempts[ip_address]["timestamps"] if timestamp - ts <= time_window]
            brute_force_attempts[ip_address]["timestamps"] = recent_attempts

            # Check if the number of recent attempts exceeds the threshold
            if len(recent_attempts) >= int(br_config["attempt_threshold"]):
                brute_force_attempts[ip_address]["blacklisted"] = True
    
    return brute_force_attempts
