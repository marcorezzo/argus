import elasticsearch
import elasticsearch.helpers
from datetime import datetime, timedelta
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('argus.conf')

# Elasticsearch configuration
sus_config = config['suspicious_transfers']

def detect_suspicious_transfers(es, index):
    now = datetime.utcnow()
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"network.bytes": {"gte": int(sus_config["threshold_size"])}}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": (now - timedelta(minutes=int(sus_config["time_window"]))).isoformat(),
                                "lte": now.isoformat()
                            }
                        }
                    }
                ]
            }
        }
    }
    results = es.search(index=index, body=query)
    for hit in results['hits']['hits']:
        print(f"Suspicious transfer detected: {hit['_source']}")
