import os
import requests
import json
from datetime import datetime
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('argus.conf')

# Elasticsearch configuration
ab_config = config['abuseipdb']
    
headers = {
    'Accept': 'application/json',
    'Key': ab_config["api_key"]
}

def fetch_blacklist():
    response = requests.get(ab_config["base_url"], headers=headers)
    return response.json()

def save_blacklist(data):
    if not os.path.exists(ab_config["shared_folder"]):
        os.makedirs(ab_config["shared_folder"])
    
    filepath = os.path.join(ab_config["shared_folder"], ab_config["blacklist_filename"])
    
    with open(filepath, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Blacklist data saved to {filepath}")

def save_fetch_date():
    filepath = os.path.join(ab_config["shared_folder"], ab_config["date_filename"])
    today_date = datetime.now().strftime('%Y%m%d')
    
    with open(filepath, 'w') as file:
        file.write(today_date)
    print(f"Fetch date saved to {filepath}")

def already_fetched_today():
    filepath = os.path.join(ab_config["shared_folder"], ab_config["date_filename"])
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            last_fetched_date = file.read().strip()
            today_date = datetime.now().strftime('%Y%m%d')
            return last_fetched_date == today_date
    return False

if __name__ == "__main__":
    if already_fetched_today():
        print("Blacklist data already fetched today.")
    else:
        data = fetch_blacklist()
        save_blacklist(data)
        save_fetch_date()

