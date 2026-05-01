#!/usr/bin/env python3

import os
import subprocess
from opensearchpy import OpenSearch

ES_HOST = "127.0.0.1"
ELASTIC_PORT = 9200

ELASTIC_USER = **************
ELASTIC_PASS = **************

STATE_FILE = "/var/lib/ml-local-agent/last_seen.txt"

es_elastic = OpenSearch(
    hosts=[{"host": ES_HOST, "port": ELASTIC_PORT}],
    http_auth=(ELASTIC_USER, ELASTIC_PASS),
    use_ssl=True,
    verify_certs=False
)

def load_last_seen():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    return None

def save_last_seen(ts):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(ts)

last_seen = load_last_seen()

query = {
    "size": 1,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {"match_all": {}}
}

res = es_elastic.search(index="ml-alerts-*", body=query)

hits = res.get("hits", {}).get("hits", [])
if not hits:
    exit(0)

alert = hits[0]["_source"]
ts = alert.get("@timestamp")

if ts == last_seen:
    exit(0)

entity = alert.get("entity_id", "unknown")
platform = alert.get("platform", "unknown")
severity = alert.get("severity", "unknown").upper()
reason = alert.get("reason", "Behavioural deviation detected")
timestamp = alert.get("@timestamp", "unknown")

message = (
    "Anomalous behaviour detected\n"
    f"Entity: {entity}\n"
    f"Platform: {platform}\n"
    f"Severity: {severity}\n"
    f"Reason: {reason}"
)

urgency_map = {
    "LOW": "low",
    "MEDIUM": "normal",
    "HIGH": "critical"
}

urgency = urgency_map.get(severity, "normal")

subprocess.run([
    "notify-send",
    "-u", urgency,
    "-i", "dialog-warning",
    "ML Security Alert",
    message
])


save_last_seen(ts)
