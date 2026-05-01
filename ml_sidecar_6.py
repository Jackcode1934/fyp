#!/usr/bin/env python3

from opensearchpy import OpenSearch, helpers
from sklearn.ensemble import IsolationForest
import pandas as pd
from datetime import datetime, timezone
import os
import joblib

ES_HOST = "127.0.0.1"

WAZUH_PORT = 9201
ELASTIC_PORT = 9200

WAZUH_USER = *******
WAZUH_PASS = *******

ELASTIC_USER = ********
ELASTIC_PASS = ********

INDICES = "wazuh-alerts-*,wazuh-events-*,wazuh-logs-oci-*"

BASELINE_RANGE = "now-7d"
SCORING_RANGE  = "now-1h"

CONTAMINATION = 0.05
RANDOM_STATE = 42

STATE_DIR = "/home/jack/ml_state"
os.makedirs(STATE_DIR, exist_ok=True)

TODAY = datetime.now(timezone.utc).strftime("%Y.%m.%d")

es_wazuh = OpenSearch(
    hosts=[{"host": ES_HOST, "port": WAZUH_PORT}],
    http_auth=(WAZUH_USER, WAZUH_PASS),
    use_ssl=True,
    verify_certs=False,
    timeout=60
)

es_elastic = OpenSearch(
    hosts=[{"host": ES_HOST, "port": ELASTIC_PORT}],
    http_auth=(ELASTIC_USER, ELASTIC_PASS),
    use_ssl=True,
    verify_certs=False,
    timeout=60,
    max_retries=3,
    retry_on_timeout=True
)

def fetch_events(time_range):
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": time_range, "lte": "now"}
            }
        },
        "_source": [
            "@timestamp",
            "rule.id",
            "rule.level",

            "agent.name",
            "host.name",
            "manager.name",

            # Windows
            "data.win.system.eventID",
            "data.win.eventdata.subjectUserName",
            "data.win.eventdata.ipAddress",

            # Linux
            "data.srcip",
            "data.dstuser",

            # OCI
            "oci.data.identity.ipAddress",
            "oci.data.identity.principalName"
        ],
        "size": 10000
    }

    resp = es_wazuh.search(index=INDICES, body=query)
    return pd.DataFrame([hit["_source"] for hit in resp["hits"]["hits"]])

def normalise(df):

    if df.empty:
        return df

    REQUIRED_FIELDS = [
        "@timestamp",
        "agent.name",
        "host.name",
        "manager.name",
        "rule.id",
        "rule.level",
        "data.win.system.eventID",
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.ipAddress",
        "data.srcip",
        "data.dstuser",
        "oci.data.identity.ipAddress",
        "oci.data.identity.principalName"
    ]

    for field in REQUIRED_FIELDS:
        if field not in df.columns:
            df[field] = ""

    df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors="coerce")

    for col in df.columns:
        if col != "@timestamp":
            df[col] = df[col].astype(str)

    # Host
    df["host"] = df["agent.name"]
    df.loc[df["host"] == "", "host"] = df["host.name"]
    df.loc[df["host"] == "", "host"] = df["manager.name"]

    # User and platform
    df["user"] = ""
    df["platform"] = ""

    win = df["data.win.system.eventID"] != ""
    df.loc[win, "user"] = df["data.win.eventdata.subjectUserName"]
    df.loc[win, "platform"] = "windows"

    linux = df["data.dstuser"] != ""
    df.loc[(df["platform"] == "") & linux, "user"] = df["data.dstuser"]
    df.loc[(df["platform"] == "") & linux, "platform"] = "linux"

    oci = df["oci.data.identity.principalName"] != ""
    df.loc[oci, "user"] = df["oci.data.identity.principalName"]
    df.loc[oci, "platform"] = "oci"

    df["src_ip"] = ""
    df.loc[df["platform"] == "windows", "src_ip"] = df["data.win.eventdata.ipAddress"]
    df.loc[df["platform"] == "linux", "src_ip"] = df["data.srcip"]
    df.loc[df["platform"] == "oci", "src_ip"] = df["oci.data.identity.ipAddress"]

    # Time features
    df["hour"] = df["@timestamp"].dt.hour.fillna(-1)
    df["off_hours"] = df["hour"].isin(list(range(0,6)) + list(range(22,24))).astype(int)

    df["rule.level"] = pd.to_numeric(df["rule.level"], errors="coerce").fillna(0)

    return df

def persistent_iforest(features, model_name):

    model_path = f"{STATE_DIR}/{model_name}.pkl"

    if features.empty or len(features) < 5:
        features["anomaly"] = 1
        return features

    if os.path.exists(model_path):
        model = joblib.load(model_path)
        features["anomaly"] = model.predict(features)
    else:
        model = IsolationForest(contamination=CONTAMINATION, random_state=RANDOM_STATE)
        features["anomaly"] = model.fit_predict(features)
        joblib.dump(model, model_path)

    return features

def build_user_features(df, platform):
    sub = df[df["platform"] == platform]
    if sub.empty:
        return pd.DataFrame()

    return sub.groupby("user").agg(
        total_events=("user", "count"),
        off_hours_ratio=("off_hours", "mean"),
        unique_rules=("rule.id", "nunique"),
        high_severity_events=("rule.level", lambda x: (x >= 10).sum())
    )

def build_host_features(df):
    sub = df[df["host"] != ""]
    if sub.empty:
        return pd.DataFrame()

    return sub.groupby("host").agg(
        total_events=("host", "count"),
        unique_users=("user", "nunique"),
        unique_rules=("rule.id", "nunique"),
        off_hours_ratio=("off_hours", "mean")
    )

def interpret_user_anomaly(row, platform):
    reasons = []

    if row["off_hours_ratio"] > 0.6:
        reasons.append("high volume of off-hours activity")
    if row["high_severity_events"] >= 5:
        reasons.append("multiple high-severity security events")
    if row["total_events"] > 150:
        reasons.append("unusually high activity volume")

    if not reasons:
        reasons.append("behaviour deviates from historical baseline")

    severity = "high" if row["high_severity_events"] >= 5 or row["off_hours_ratio"] > 0.7 else "medium"
    reason = f"Anomalous {platform} user behaviour detected: " + ", ".join(reasons)

    return severity, reason

def interpret_host_anomaly(row):
    reasons = []

    if row["unique_users"] >= 6:
        reasons.append("unusually high number of distinct users")
    if row["off_hours_ratio"] > 0.6:
        reasons.append("significant off-hours activity")
    if row["total_events"] > 300:
        reasons.append("high overall activity volume")

    if not reasons:
        reasons.append("multi-dimensional behaviour deviates from baseline")

    severity = "high" if row["unique_users"] >= 6 else "medium"
    reason = "Anomalous host behaviour detected: " + ", ".join(reasons)

    return severity, reason

baseline_df = normalise(fetch_events(BASELINE_RANGE))
recent_df   = normalise(fetch_events(SCORING_RANGE))

if baseline_df.empty or recent_df.empty:
    print("No data available")
    exit(0)

recent_df = recent_df[recent_df["rule.level"] >= 7]

actions = []

# ---------- USER MODELS ----------
for platform in ["windows", "linux", "oci"]:
    feats = build_user_features(baseline_df, platform)
    if feats.empty:
        continue

    scored = persistent_iforest(feats.copy(), f"{platform}_user_model")
    anomalies = scored[scored["anomaly"] == -1]

    for entity, row in anomalies.iterrows():
        severity, reason = interpret_user_anomaly(row, platform)

        actions.append({
            "_index": f"ml-alerts-{platform}-user-{TODAY}",
            "_source": {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "entity_type": "user",
                "entity_id": entity,
                "platform": platform,
                "model": "IsolationForest",
                "anomaly": -1,
                "severity": severity,
                "reason": reason,
                "features": row.drop("anomaly").to_dict(),
                "investigation_hint": "Correlate with wazuh-alerts-* and wazuh-events-*"
            }
        })

# ---------- HOST MODEL ----------
host_feats = build_host_features(baseline_df)
if not host_feats.empty:
    host_scored = persistent_iforest(host_feats.copy(), "host_model")
    host_anoms = host_scored[host_scored["anomaly"] == -1]

    for host, row in host_anoms.iterrows():
        severity, reason = interpret_host_anomaly(row)

        actions.append({
            "_index": f"ml-alerts-host-{TODAY}",
            "_source": {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "entity_type": "host",
                "entity_id": host,
                "platform": "cross-platform",
                "model": "IsolationForest",
                "anomaly": -1,
                "severity": severity,
                "reason": reason,
                "features": row.drop("anomaly").to_dict(),
                "investigation_hint": "Investigate potential lateral movement or shared access"
            }
        })

# ---------- CROSS SERVICE LINKING (LINUX SSH and  OCI) ----------
linux_ips = set(recent_df[recent_df["platform"] == "linux"]["src_ip"])
oci_ips   = set(recent_df[recent_df["platform"] == "oci"]["src_ip"])

for ip in linux_ips & oci_ips:
    actions.append({
        "_index": f"ml-alerts-cross-platform-{TODAY}",
        "_source": {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "entity_type": "ip",
            "entity_id": ip,
            "platform": "linux+oci",
            "model": "RuleCorrelated",
            "severity": "high",
            "reason": (
                "Failed authentication activity observed on both Linux SSH "
                "and OCI identity services from the same source IP"
            ),
            "investigation_hint": "Investigate for credential abuse or lateral movement"
        }
    })

if actions:
    helpers.bulk(
        es_elastic,
        actions,
        chunk_size=50,
        request_timeout=60,
        raise_on_error=False
    )

print(" ML SIDECAR COMPLETE")
