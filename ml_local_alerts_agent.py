#!/usr/bin/env python3

import os
import json
import subprocess
import urllib3
from opensearchpy import OpenSearch


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ES_HOST = "127.0.0.1"
ELASTIC_PORT = 9200

ELASTIC_USER = **************
ELASTIC_PASS = **************

STATE_DIR = "/var/lib/ml-local-agent"
SEEN_FILE = f"{STATE_DIR}/seen_alerts.json"

MAX_SEEN = 500

es_elastic = OpenSearch(
    hosts=[{"host": ES_HOST, "port": ELASTIC_PORT}],
    http_auth=(ELASTIC_USER, ELASTIC_PASS),
    use_ssl=True,
    verify_certs=False,
    timeout=30,
    max_retries=3,
    retry_on_timeout=True
)


def load_seen():
    if not os.path.exists(SEEN_FILE):
        return set()

    try:
        with open(SEEN_FILE, "r") as f:
            data = json.load(f)

        return set(data)

    except Exception:
        return set()


def save_seen(seen):
    os.makedirs(STATE_DIR, exist_ok=True)

    seen_list = list(seen)[-MAX_SEEN:]

    with open(SEEN_FILE, "w") as f:
        json.dump(seen_list, f, indent=2)


def severity_to_urgency(severity):
    severity = str(severity).upper()

    if severity in ["CRITICAL", "HIGH"]:
        return "critical"

    if severity == "MEDIUM":
        return "normal"

    return "low"


def send_notification(alert):
    entity = alert.get("entity_id", "unknown")
    entity_type = alert.get("entity_type", "unknown")
    platform = alert.get("platform", "unknown")
    severity = str(alert.get("severity", "unknown")).upper()
    score = alert.get("score", "n/a")
    reason = alert.get("reason", "Behavioural deviation detected")

    affected_hosts = alert.get("affected_hosts", [])
    observed_source_ips = alert.get("observed_source_ips", [])

    if isinstance(affected_hosts, list):
        affected_hosts_text = ", ".join(affected_hosts[:5]) if affected_hosts else "n/a"
    else:
        affected_hosts_text = str(affected_hosts)

    if isinstance(observed_source_ips, list):
        source_ips_text = ", ".join(observed_source_ips[:5]) if observed_source_ips else "n/a"
    else:
        source_ips_text = str(observed_source_ips)

    message = (
        f"Entity: {entity} ({entity_type})\n"
        f"Platform: {platform}\n"
        f"Severity: {severity}\n"
        f"Score: {score}\n"
        f"Hosts: {affected_hosts_text}\n"
        f"Source IPs: {source_ips_text}\n"
        f"Reason: {reason}"
    )

    urgency = severity_to_urgency(severity)

    subprocess.run([
        "notify-send",
        "-u", urgency,
        "-i", "dialog-warning",
        "ML Security Alert",
        message
    ], check=False)


def main():
    seen = load_seen()

    query = {
        "size": 20,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-24h",
                                "lte": "now"
                            }
                        }
                    }
                ],
                "should": [
                    {
                        "terms": {
                            "severity.keyword": [
                                "high",
                                "critical"
                            ]
                        }
                    },
                    {
                        "range": {
                            "score": {
                                "gte": 0.65
                            }
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        }
    }

    res = es_elastic.search(index="ml-alerts-*", body=query)

    hits = res.get("hits", {}).get("hits", [])

    if not hits:
        return

    new_seen = set(seen)

    # Send oldest first so notifications are in chronological order
    for hit in reversed(hits):
        alert = hit.get("_source", {})
        elastic_id = hit.get("_id")

        alert_key = alert.get("alert_key") or elastic_id

        if not alert_key:
            continue

        if alert_key in seen:
            continue

        send_notification(alert)
        new_seen.add(alert_key)

    save_seen(new_seen)


if __name__ == "__main__":
    main()
