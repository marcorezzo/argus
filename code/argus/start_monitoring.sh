#!/bin/bash

# Function to check if Elasticsearch is reachable
function wait_for_elasticsearch {
  echo "Waiting for Elasticsearch to be reachable..."
  until curl -u elastic:argusIsTheBest123 -s -o /dev/null -w "%{http_code}" http://172.19.0.2:9200/_cluster/health | grep -q "200"; do
    sleep 5
  done
  echo "Elasticsearch is reachable!"
}

# Function to check if Kibana is available
function wait_for_kibana {
  echo "Waiting for Kibana to be available..."
  until curl -u elastic:argusIsTheBest123 -s -o /dev/null -w "%{http_code}" http://172.19.0.3:5601/api/status | grep -q "200"; do
    sleep 5
  done
  echo "Kibana is available!"
}

# Wait for Elasticsearch to be reachable
wait_for_elasticsearch

# Wait for Kibana to be available
wait_for_kibana

# Fetch data from abuseIPDB
python3 /argus/abuseIPDB.py

# Start the monitoring script every 10 seconds 
while true; do
  python3 /argus/monitor.py 
  sleep 10
done

