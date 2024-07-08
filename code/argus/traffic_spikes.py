from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import os
import json
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('argus.conf')

# Elasticsearch configuration
tr_config = config['traffic_spikes']


def detect_traffic_spikes(es, index):
    # Define the query for fetching recent logs
    now = datetime.now()
    time_frame = now - timedelta(minutes=int(tr_config["time_window"]))

    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": time_frame, "lte": now}
            }
        }
    }

    # Fetch recent logs
    recent_traffic_count = 0
    for hit in scan(es, index=index, query=query, scroll='2m', size=100):
        recent_traffic_count += 1
        
    print("Recent traffic count:", recent_traffic_count)

    # Fetch logs from 15 to 30 minutes ago for comparison
    previous_query = {
        "query": {
            "range": {
                "@timestamp": {"gte": time_frame - timedelta(minutes=int(tr_config["time_window"])), "lt": time_frame}
            }
        }
    }

    previous_traffic_count = 0
    for hit in scan(es, index=index, query=previous_query, scroll='2m', size=100):
        previous_traffic_count += 1
        
    print("Previous traffic count:", previous_traffic_count)

    # Calculate traffic increase percentage
    if previous_traffic_count > 0:
        traffic_increase_percentage = ((recent_traffic_count - previous_traffic_count) / previous_traffic_count) * 100
    else:
        # If there were no previous logs, consider it as a spike
        traffic_increase_percentage = 100

    print("Traffic increase percentage:", traffic_increase_percentage)

    # Define a threshold for traffic spikes
    is_spike = traffic_increase_percentage > int(tr_config["threshold"])

    return {
        "recent_traffic_count": recent_traffic_count,
        "previous_traffic_count": previous_traffic_count,
        "traffic_increase_percentage": traffic_increase_percentage,
        "is_spike": is_spike
    }
