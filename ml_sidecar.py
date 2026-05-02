#!/usr/bin/env python3

from opensearchpy import OpenSearch, helpers
from sklearn.ensemble import IsolationForest
import pandas as pd
from datetime import datetime, timezone
import os
import joblib
import traceback
import hashlib
import math



ES_HOST = "127.0.0.1"
ELASTIC_PORT = 9200

ELASTIC_USER = *********************
ELASTIC_PASS = *********************

ENDPOINT_INDICES = "wazuh-alerts-*,wazuh-events-*"
OCI_INDICES = "wazuh-logs-oci-*"

BASELINE_RANGE = "now-7d"
SCORING_RANGE = "now-24h"

CONTAMINATION = 0.05
RANDOM_STATE = 42

STATE_DIR = "/home/jack/ml_state"
os.makedirs(STATE_DIR, exist_ok=True)

TODAY = datetime.now(timezone.utc).strftime("%Y.%m.%d")
RUN_TIMESTAMP = datetime.now(timezone.utc).isoformat()

DEBUG = True


es_elastic = OpenSearch(
    hosts=[{"host": ES_HOST, "port": ELASTIC_PORT}],
    http_auth=(ELASTIC_USER, ELASTIC_PASS),
    use_ssl=True,
    verify_certs=False,
    timeout=60,
    max_retries=3,
    retry_on_timeout=True
)


def debug_print(title, value=None):
    if not DEBUG:
        return

    print("\n" + "-" * 70)
    print(f"[DEBUG] {title}")
    print("-" * 70)

    if value is not None:
        print(value)


def safe_value_counts(df, col):
    if df.empty or col not in df.columns:
        return "No data / column missing"

    return df[col].value_counts(dropna=False)


def list_matching_indices(client, pattern, label):
    try:
        print(f"\n[DEBUG] Checking indices on {label}: {pattern}")
        result = client.cat.indices(index=pattern, format="json")

        if not result:
            print(f"[WARN] No indices matched {pattern} on {label}")
            return

        for idx in result:
            print(
                f"  {idx.get('index')} "
                f"docs={idx.get('docs.count')} "
                f"health={idx.get('health')}"
            )

    except Exception as e:
        print(f"[ERROR] Could not list indices on {label}: {e}")


def expand_ip_set(series):
    ips = set()

    for value in series.dropna().astype(str):
        for part in value.split(","):
            ip = part.strip()

            if ip and ip not in ["-", "None", "nan", "null"]:
                ips.add(ip)

    return ips


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}

    if isinstance(value, list):
        return [json_safe(v) for v in value]

    if isinstance(value, tuple):
        return [json_safe(v) for v in value]

    if isinstance(value, pd.Timestamp):
        return value.isoformat()

    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    return value


def clean_dict(input_dict):
    return {str(k): json_safe(v) for k, v in input_dict.items()}


def make_alert_key(platform, entity_type, entity_id):
    clean_entity = str(entity_id)
    clean_entity = clean_entity.replace(" ", "_")
    clean_entity = clean_entity.replace("/", "_")
    clean_entity = clean_entity.replace("|", "_")

    return f"{platform}|{entity_type}|{clean_entity}|{TODAY}"


def make_alert_id(alert_key):
    return hashlib.sha1(alert_key.encode("utf-8")).hexdigest()


def ip_value_contains(ip_value, target_ip):
    parts = str(ip_value).split(",")

    for part in parts:
        if part.strip() == str(target_ip):
            return True

    return False


def add_alert_if_new(actions, action):
    index_name = action.get("_index")
    alert_id = action.get("_id")

    if not index_name or not alert_id:
        actions.append(action)
        return True

    try:
        already_exists = es_elastic.exists(
            index=index_name,
            id=alert_id
        )
    except Exception as e:
        print(f"[WARN] Could not check if alert exists: {index_name}/{alert_id}")
        print(str(e))
        already_exists = False

    if already_exists:
        print(f"[DEBUG] Suppressing duplicate alert: {index_name}/{alert_id}")
        return False

    action["_op_type"] = "create"
    actions.append(action)

    return True



def source_fields():
    return [
        "@timestamp",
        "rule.id",
        "rule.level",
        "rule.description",
        "agent.name",
        "host.name",
        "manager.name",
        "data.win.system.eventID",
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.ipAddress",
        "data.win.eventdata.workstationName",
        "data.srcip",
        "data.dstuser",
        "data.srcuser",
        "data.user",
        "source.ip",
        "srcip",
        "user.name",
        "cloud.provider",
        "event.dataset",
        "event.action",
        "event.outcome",
        "integration",
        "observer.product",
        "observer.vendor",
        "observer.type",
        "oci.type",
        "oci.source",
        "oci.data.identity.ipAddress",
        "oci.data.identity.principalName",
        "oci.data.identity.principalId",
        "oci.data.identity.callerName",
        "oci.data.request.action",
        "oci.data.response.status",
        "oci.data.eventName",
        "oci.data.message",
        "full_log",
        "message"
    ]



def fetch_events(index_pattern, time_range):
    base_query = {
        "range": {
            "@timestamp": {
                "gte": time_range,
                "lte": "now"
            }
        }
    }

    if index_pattern == ENDPOINT_INDICES:
        query_clause = {
            "bool": {
                "must": [
                    base_query
                ],
                "should": [
                    {"exists": {"field": "data.win.system.eventID"}},
                    {"exists": {"field": "data.srcip"}},
                    {"match_phrase": {"full_log": "Failed password"}},
                    {"match_phrase": {"full_log": "Invalid user"}},
                    {"match_phrase": {"full_log": "sshd"}},
                    {"match_phrase": {"full_log": "rhost="}}
                ],
                "minimum_should_match": 1
            }
        }
    else:
        query_clause = base_query

    query = {
        "query": query_clause,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "_source": source_fields(),
        "size": 10000
    }

    print(f"\n[DEBUG] Fetching events from {index_pattern} for range {time_range}")

    try:
        resp = es_elastic.search(index=index_pattern, body=query)
    except Exception as e:
        print("[ERROR] Search failed")
        print(str(e))
        return pd.DataFrame()

    hits = resp.get("hits", {}).get("hits", [])
    print(f"[DEBUG] Hits returned from {index_pattern}: {len(hits)}")

    if not hits:
        return pd.DataFrame()

    docs = [hit["_source"] for hit in hits]

    return pd.json_normalize(docs)


def fetch_linux_ssh_events(time_range):
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": time_range,
                                "lte": "now"
                            }
                        }
                    },
                    {
                        "exists": {
                            "field": "data.srcip"
                        }
                    }
                ],
                "should": [
                    {"match_phrase": {"full_log": "Failed password"}},
                    {"match_phrase": {"full_log": "Invalid user"}},
                    {"match_phrase": {"full_log": "sshd"}}
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "_source": source_fields(),
        "size": 5000
    }

    print(f"\n[DEBUG] Fetching dedicated Linux SSH events for range {time_range}")

    try:
        resp = es_elastic.search(index=ENDPOINT_INDICES, body=query)
    except Exception as e:
        print("[ERROR] Linux SSH search failed")
        print(str(e))
        return pd.DataFrame()

    hits = resp.get("hits", {}).get("hits", [])
    print(f"[DEBUG] Dedicated Linux SSH hits returned: {len(hits)}")

    if not hits:
        return pd.DataFrame()

    docs = [hit["_source"] for hit in hits]

    return pd.json_normalize(docs)



def normalise(df):
    if df.empty:
        return df

    required_fields = source_fields()

    for field in required_fields:
        if field not in df.columns:
            df[field] = ""

    df["@timestamp"] = pd.to_datetime(
        df["@timestamp"],
        errors="coerce",
        utc=True
    )

    for col in df.columns:
        if col != "@timestamp":
            df[col] = df[col].fillna("").astype(str)

    df["host"] = df["agent.name"]
    df.loc[df["host"] == "", "host"] = df["host.name"]
    df.loc[df["host"] == "", "host"] = df["manager.name"]

    df["platform"] = ""
    df["user"] = ""

    win = df["data.win.system.eventID"] != ""

    df.loc[win, "platform"] = "windows"
    df.loc[win, "user"] = df["data.win.eventdata.targetUserName"]

    df.loc[
        win & (df["user"] == ""),
        "user"
    ] = df["data.win.eventdata.subjectUserName"]

    oci = (
        (df["cloud.provider"].str.lower() == "oci") |
        (df["event.dataset"].str.lower() == "oci.audit") |
        (df["integration"].str.lower() == "oci") |
        (df["observer.product"].str.lower() == "oci") |
        (df["observer.vendor"].str.lower() == "oracle") |
        (df["oci.data.identity.principalName"] != "") |
        (df["oci.data.identity.ipAddress"] != "") |
        (df["oci.source"] != "") |
        (df["oci.type"] != "")
    )

    df.loc[oci, "platform"] = "oci"
    df.loc[oci, "user"] = df["oci.data.identity.principalName"]

    df.loc[
        oci & (df["user"] == ""),
        "user"
    ] = df["user.name"]

    df.loc[
        oci & (df["user"] == ""),
        "user"
    ] = df["oci.data.identity.principalId"]

    df.loc[
        oci & (df["user"] == ""),
        "user"
    ] = df["oci.data.identity.callerName"]

    linux = (
        (
            (df["data.dstuser"] != "") |
            (df["data.srcuser"] != "") |
            (df["data.user"] != "") |
            (df["data.srcip"] != "") |
            (df["srcip"] != "") |
            (df["full_log"].str.contains("sshd", case=False, na=False)) |
            (df["full_log"].str.contains("pam_unix", case=False, na=False))
        )
        &
        (df["platform"] == "")
    )

    df.loc[linux, "platform"] = "linux"

    df.loc[
        (df["platform"] == "linux") & (df["user"] == ""),
        "user"
    ] = df["data.dstuser"]

    df.loc[
        (df["platform"] == "linux") & (df["user"] == ""),
        "user"
    ] = df["data.srcuser"]

    df.loc[
        (df["platform"] == "linux") & (df["user"] == ""),
        "user"
    ] = df["data.user"]

    linux_missing_user = (df["platform"] == "linux") & (df["user"] == "")

    extracted_linux_users = df.loc[
        linux_missing_user,
        "full_log"
    ].str.extract(
        r"invalid user\s+([A-Za-z0-9._-]+)"
    )[0]

    df.loc[linux_missing_user, "user"] = extracted_linux_users.fillna("")

    df["src_ip"] = ""

    df.loc[
        df["platform"] == "windows",
        "src_ip"
    ] = df["data.win.eventdata.ipAddress"]

    df.loc[
        df["platform"] == "linux",
        "src_ip"
    ] = df["data.srcip"]

    df.loc[
        (df["platform"] == "linux") & (df["src_ip"] == ""),
        "src_ip"
    ] = df["srcip"]

    df.loc[
        df["platform"] == "oci",
        "src_ip"
    ] = df["oci.data.identity.ipAddress"]

    df.loc[
        (df["platform"] == "oci") & (df["src_ip"] == ""),
        "src_ip"
    ] = df["source.ip"]

    df.loc[
        (df["platform"] == "oci") & (df["src_ip"] == ""),
        "src_ip"
    ] = df["srcip"]

    df.loc[
        df["src_ip"].isin(["-", "None", "nan", "null", ""]),
        "src_ip"
    ] = ""

    linux_missing_ip = (df["platform"] == "linux") & (df["src_ip"] == "")

    extracted_linux_ips = df.loc[
        linux_missing_ip,
        "full_log"
    ].str.extract(
        r"(?:from|rhost=)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
    )[0]

    df.loc[linux_missing_ip, "src_ip"] = extracted_linux_ips.fillna("")

    df.loc[
        df["src_ip"].isin(["-", "None", "nan", "null", ""]),
        "src_ip"
    ] = ""

    df["hour"] = df["@timestamp"].dt.hour.fillna(-1)

    df["off_hours"] = df["hour"].isin(
        list(range(0, 6)) + list(range(22, 24))
    ).astype(int)

    df["rule.level"] = pd.to_numeric(
        df["rule.level"],
        errors="coerce"
    ).fillna(0)

    return df


def empty_context():
    return {
        "affected_hosts": [],
        "observed_source_ips": [],
        "event_count": 0,
        "first_seen": None,
        "last_seen": None,
        "sample_events": []
    }


def get_entity_context(df, platform, entity_type, entity_id):
    entity_id = str(entity_id)

    if df.empty:
        return empty_context()

    if entity_type == "user":
        sub = df[
            (df["platform"] == platform) &
            (df["user"] == entity_id)
        ]

    elif entity_type == "host":
        sub = df[df["host"] == entity_id]

    elif entity_type == "ip":
        sub = df[
            df["src_ip"].astype(str).apply(
                lambda value: ip_value_contains(value, entity_id)
            )
        ]

    else:
        sub = pd.DataFrame()

    if sub.empty:
        return empty_context()

    timestamps = sub["@timestamp"].dropna().sort_values()

    affected_hosts = sorted(
        [x for x in sub["host"].dropna().astype(str).unique().tolist() if x]
    )

    observed_source_ips = sorted(
        [x for x in expand_ip_set(sub["src_ip"]) if x]
    )

    sample_events = []

    sample_df = sub.sort_values("@timestamp", ascending=False).head(5)

    for _, event in sample_df.iterrows():
        sample_events.append({
            "timestamp": str(event.get("@timestamp", "")),
            "platform": str(event.get("platform", "")),
            "host": str(event.get("host", "")),
            "user": str(event.get("user", "")),
            "src_ip": str(event.get("src_ip", "")),
            "rule_id": str(event.get("rule.id", "")),
            "rule_level": json_safe(event.get("rule.level", 0)),
            "rule_description": str(event.get("rule.description", "")),
            "full_log": str(event.get("full_log", ""))[:500]
        })

    return {
        "affected_hosts": affected_hosts,
        "observed_source_ips": observed_source_ips,
        "event_count": int(len(sub)),
        "first_seen": timestamps.iloc[0].isoformat() if len(timestamps) else None,
        "last_seen": timestamps.iloc[-1].isoformat() if len(timestamps) else None,
        "sample_events": sample_events
    }


def build_user_features(df, platform):
    sub = df[
        (df["platform"] == platform) &
        (df["user"] != "")
    ]

    if sub.empty:
        return pd.DataFrame()

    return sub.groupby("user").agg(
        total_events=("user", "count"),
        off_hours_ratio=("off_hours", "mean"),
        unique_rules=("rule.id", "nunique"),
        high_severity_events=("rule.level", lambda x: (x >= 10).sum()),
        unique_source_ips=("src_ip", lambda x: x[x != ""].nunique())
    )


def build_host_features(df):
    sub = df[df["host"] != ""]

    if sub.empty:
        return pd.DataFrame()

    return sub.groupby("host").agg(
        total_events=("host", "count"),
        unique_users=("user", lambda x: x[x != ""].nunique()),
        unique_rules=("rule.id", "nunique"),
        off_hours_ratio=("off_hours", "mean"),
        high_severity_events=("rule.level", lambda x: (x >= 10).sum())
    )



def train_and_score_iforest(baseline_features, scoring_features, model_name):
    model_path = f"{STATE_DIR}/{model_name}.pkl"

    if baseline_features.empty:
        print(f"[WARN] {model_name}: baseline features empty")
        scoring_features["anomaly"] = 1
        scoring_features["score"] = 0.0
        return scoring_features

    if scoring_features.empty:
        print(f"[WARN] {model_name}: scoring features empty")
        scoring_features["anomaly"] = 1
        scoring_features["score"] = 0.0
        return scoring_features

    if len(baseline_features) < 3:
        print(
            f"[WARN] {model_name}: fewer than 3 baseline entities; "
            "skipping anomaly scoring"
        )
        scoring_features["anomaly"] = 1
        scoring_features["score"] = 0.0
        return scoring_features

    feature_columns = baseline_features.columns.tolist()

    baseline_features = baseline_features.apply(
        pd.to_numeric,
        errors="coerce"
    ).fillna(0)

    scoring_features = scoring_features.reindex(
        columns=feature_columns,
        fill_value=0
    )

    scoring_features = scoring_features.apply(
        pd.to_numeric,
        errors="coerce"
    ).fillna(0)

    if os.path.exists(model_path):
        print(f"[DEBUG] Loading existing model: {model_path}")
        model = joblib.load(model_path)
    else:
        print(f"[DEBUG] Training new model: {model_name}")
        model = IsolationForest(
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE
        )
        model.fit(baseline_features)
        joblib.dump(model, model_path)

    predictions = model.predict(scoring_features)
    raw_scores = model.decision_function(scoring_features)

    risk_scores = -raw_scores

    min_score = risk_scores.min()
    max_score = risk_scores.max()

    if max_score > min_score:
        norm_scores = (risk_scores - min_score) / (max_score - min_score)
    else:
        norm_scores = pd.Series(
            [1.0 if p == -1 else 0.0 for p in predictions],
            index=scoring_features.index
        )

    scoring_features["anomaly"] = predictions

    scoring_features["score"] = pd.Series(
        norm_scores,
        index=scoring_features.index
    ).round(4)

    return scoring_features


def severity_from_score(score):
    score = float(score)

    if score >= 0.85:
        return "critical"

    if score >= 0.65:
        return "high"

    if score >= 0.35:
        return "medium"

    return "low"


def interpret_user_anomaly(row, platform):
    reasons = []

    if row.get("off_hours_ratio", 0) > 0.6:
        reasons.append("high volume of off-hours activity")

    if row.get("high_severity_events", 0) >= 5:
        reasons.append("multiple high-severity security events")

    if row.get("total_events", 0) > 150:
        reasons.append("unusually high activity volume")

    if row.get("unique_source_ips", 0) >= 3:
        reasons.append("activity observed from multiple source IP addresses")

    if not reasons:
        reasons.append("behaviour deviates from historical baseline")

    severity = severity_from_score(row.get("score", 0))

    reason = (
        f"Anomalous {platform} user behaviour detected: "
        + ", ".join(reasons)
    )

    return severity, reason


def interpret_host_anomaly(row):
    reasons = []

    if row.get("unique_users", 0) >= 6:
        reasons.append("unusually high number of distinct users")

    if row.get("off_hours_ratio", 0) > 0.6:
        reasons.append("significant off-hours activity")

    if row.get("total_events", 0) > 300:
        reasons.append("high overall activity volume")

    if row.get("high_severity_events", 0) >= 5:
        reasons.append("multiple high-severity events associated with host")

    if not reasons:
        reasons.append("multi-dimensional behaviour deviates from baseline")

    severity = severity_from_score(row.get("score", 0))

    reason = "Anomalous host behaviour detected: " + ", ".join(reasons)

    return severity, reason


def build_user_alert(platform, entity, row, severity, reason, recent_df):
    alert_key = make_alert_key(platform, "user", entity)
    alert_id = make_alert_id(alert_key)

    context = get_entity_context(
        recent_df,
        platform=platform,
        entity_type="user",
        entity_id=entity
    )

    features = clean_dict(row.drop(["anomaly", "score"]).to_dict())

    primary_host = (
        context["affected_hosts"][0]
        if context["affected_hosts"]
        else "unknown"
    )

    primary_source_ip = (
        context["observed_source_ips"][0]
        if context["observed_source_ips"]
        else "unknown"
    )

    return {
        "_op_type": "create",
        "_index": f"ml-alerts-{platform}-user-{TODAY}",
        "_id": alert_id,
        "_source": {
            "@timestamp": context["last_seen"] or RUN_TIMESTAMP,
            "created_at": RUN_TIMESTAMP,

            "alert_key": alert_key,
            "alert_id": alert_id,
            "deduplicated": True,
            "alert_status": "active",

            "summary": (
                f"{severity.upper()} {platform} user anomaly for {entity}: "
                f"{reason}"
            ),

            "entity_type": "user",
            "entity_id": str(entity),
            "platform": platform,

            "primary_host": primary_host,
            "primary_source_ip": primary_source_ip,

            "model": "IsolationForest",
            "anomaly": -1,
            "score": float(row["score"]),
            "severity": severity,
            "reason": reason,

            "features": features,

            "analysis_window": {
                "baseline": BASELINE_RANGE,
                "scoring": SCORING_RANGE,
                "run_timestamp": RUN_TIMESTAMP
            },

            "affected_hosts": context["affected_hosts"],
            "observed_source_ips": context["observed_source_ips"],
            "event_count": context["event_count"],
            "first_seen": context["first_seen"],
            "last_seen": context["last_seen"],
            "sample_events": context["sample_events"],

            "investigation_hint": (
                "Review affected_hosts, observed_source_ips and sample_events. "
                "Correlate with wazuh-alerts-* and wazuh-events-* for raw evidence."
            )
        }
    }


def build_host_alert(host, row, severity, reason, recent_df):
    alert_key = make_alert_key("cross-platform", "host", host)
    alert_id = make_alert_id(alert_key)

    context = get_entity_context(
        recent_df,
        platform="cross-platform",
        entity_type="host",
        entity_id=host
    )

    features = clean_dict(row.drop(["anomaly", "score"]).to_dict())

    primary_host = (
        context["affected_hosts"][0]
        if context["affected_hosts"]
        else str(host)
    )

    primary_source_ip = (
        context["observed_source_ips"][0]
        if context["observed_source_ips"]
        else "unknown"
    )

    return {
        "_op_type": "create",
        "_index": f"ml-alerts-host-{TODAY}",
        "_id": alert_id,
        "_source": {
            "@timestamp": context["last_seen"] or RUN_TIMESTAMP,
            "created_at": RUN_TIMESTAMP,

            "alert_key": alert_key,
            "alert_id": alert_id,
            "deduplicated": True,
            "alert_status": "active",

            "summary": (
                f"{severity.upper()} host anomaly for {host}: {reason}"
            ),

            "entity_type": "host",
            "entity_id": str(host),
            "platform": "cross-platform",

            "primary_host": primary_host,
            "primary_source_ip": primary_source_ip,

            "model": "IsolationForest",
            "anomaly": -1,
            "score": float(row["score"]),
            "severity": severity,
            "reason": reason,

            "features": features,

            "analysis_window": {
                "baseline": BASELINE_RANGE,
                "scoring": SCORING_RANGE,
                "run_timestamp": RUN_TIMESTAMP
            },

            "affected_hosts": context["affected_hosts"],
            "observed_source_ips": context["observed_source_ips"],
            "event_count": context["event_count"],
            "first_seen": context["first_seen"],
            "last_seen": context["last_seen"],
            "sample_events": context["sample_events"],

            "investigation_hint": (
                "Review host-level activity, unique users, rule diversity "
                "and sample events."
            )
        }
    }


def build_correlation_alert(ip, recent_df):
    alert_key = make_alert_key("linux+oci", "ip", ip)
    alert_id = make_alert_id(alert_key)

    context = get_entity_context(
        recent_df,
        platform="linux+oci",
        entity_type="ip",
        entity_id=ip
    )

    primary_host = (
        context["affected_hosts"][0]
        if context["affected_hosts"]
        else "unknown"
    )

    return {
        "_op_type": "create",
        "_index": f"ml-alerts-cross-platform-{TODAY}",
        "_id": alert_id,
        "_source": {
            "@timestamp": context["last_seen"] or RUN_TIMESTAMP,
            "created_at": RUN_TIMESTAMP,

            "alert_key": alert_key,
            "alert_id": alert_id,
            "deduplicated": True,
            "alert_status": "active",

            "summary": (
                f"HIGH cross-platform correlation for source IP {ip}: "
                "Linux SSH and OCI identity activity observed from same IP"
            ),

            "entity_type": "ip",
            "entity_id": str(ip),
            "platform": "linux+oci",

            "primary_host": primary_host,
            "primary_source_ip": str(ip),

            "model": "RuleCorrelated",
            "score": 1.0,
            "severity": "high",
            "reason": (
                "Failed authentication activity observed on both Linux SSH "
                "and OCI identity services from the same source IP"
            ),

            "analysis_window": {
                "baseline": BASELINE_RANGE,
                "scoring": SCORING_RANGE,
                "run_timestamp": RUN_TIMESTAMP
            },

            "affected_hosts": context["affected_hosts"],
            "observed_source_ips": [str(ip)],
            "event_count": context["event_count"],
            "first_seen": context["first_seen"],
            "last_seen": context["last_seen"],
            "sample_events": context["sample_events"],

            "investigation_hint": (
                "Review Linux SSH failures and OCI audit activity from this IP. "
                "Assess for credential abuse, password spraying or lateral movement."
            )
        }
    }

def main():
    print("\nML SIDECAR STARTED")
    print(f"Baseline range: {BASELINE_RANGE}")
    print(f"Scoring range:  {SCORING_RANGE}")
    print(f"Output date:    {TODAY}")

    list_matching_indices(
        es_elastic,
        "wazuh-*",
        "Elasticsearch source indices"
    )

    list_matching_indices(
        es_elastic,
        "ml-alerts-*",
        "Elasticsearch ML alert indices"
    )

    baseline_endpoint_raw = fetch_events(ENDPOINT_INDICES, BASELINE_RANGE)
    baseline_oci_raw = fetch_events(OCI_INDICES, BASELINE_RANGE)
    baseline_linux_ssh_raw = fetch_linux_ssh_events(BASELINE_RANGE)

    recent_endpoint_raw = fetch_events(ENDPOINT_INDICES, SCORING_RANGE)
    recent_oci_raw = fetch_events(OCI_INDICES, SCORING_RANGE)
    recent_linux_ssh_raw = fetch_linux_ssh_events(SCORING_RANGE)

    baseline_raw = pd.concat(
        [
            baseline_endpoint_raw,
            baseline_oci_raw,
            baseline_linux_ssh_raw
        ],
        ignore_index=True
    )

    recent_raw = pd.concat(
        [
            recent_endpoint_raw,
            recent_oci_raw,
            recent_linux_ssh_raw
        ],
        ignore_index=True
    )

    debug_print("Raw baseline endpoint rows", len(baseline_endpoint_raw))
    debug_print("Raw baseline OCI rows", len(baseline_oci_raw))
    debug_print("Raw baseline Linux SSH rows", len(baseline_linux_ssh_raw))

    debug_print("Raw recent endpoint rows", len(recent_endpoint_raw))
    debug_print("Raw recent OCI rows", len(recent_oci_raw))
    debug_print("Raw recent Linux SSH rows", len(recent_linux_ssh_raw))

    debug_print("Combined raw baseline rows", len(baseline_raw))
    debug_print("Combined raw recent rows", len(recent_raw))

    baseline_df = normalise(baseline_raw)
    recent_df = normalise(recent_raw)

    if baseline_df.empty or recent_df.empty:
        print("[WARN] No data available after fetch/normalise")
        print(f"Baseline empty: {baseline_df.empty}")
        print(f"Recent empty:   {recent_df.empty}")
        return

    debug_print("Baseline rows after normalise", len(baseline_df))
    debug_print("Recent rows after normalise", len(recent_df))

    debug_print(
        "Baseline platform counts",
        safe_value_counts(baseline_df, "platform")
    )

    debug_print(
        "Recent platform counts before scoring filter",
        safe_value_counts(recent_df, "platform")
    )

    debug_print(
        "Recent normalised sample",
        recent_df[
            ["@timestamp", "platform", "user", "src_ip", "host", "rule.level"]
        ].head(30)
    )

    debug_print(
        "Recent Linux rows after source IP normalisation",
        recent_df[recent_df["platform"] == "linux"][
            ["@timestamp", "user", "src_ip", "host", "rule.level", "full_log"]
        ].head(20)
    )

    recent_all_df = recent_df.copy()
    recent_scoring_df = recent_df[recent_df["platform"] != ""].copy()

    debug_print("Recent rows used for ML scoring", len(recent_scoring_df))

    debug_print(
        "Recent platform counts used for ML scoring",
        safe_value_counts(recent_scoring_df, "platform")
    )

    actions = []

    if recent_scoring_df.empty:
        print("[WARN] No recent recognised-platform events for ML scoring")
    else:
        for platform in ["windows", "linux", "oci"]:
            print(f"\n[DEBUG] Processing user model for platform: {platform}")

            baseline_feats = build_user_features(baseline_df, platform)
            recent_feats = build_user_features(recent_scoring_df, platform)

            debug_print(f"{platform} baseline user features", baseline_feats)
            debug_print(f"{platform} recent user features", recent_feats)

            if baseline_feats.empty or recent_feats.empty:
                print(
                    f"[WARN] Skipping {platform} user model "
                    "due to empty features"
                )
                continue

            scored = train_and_score_iforest(
                baseline_feats.copy(),
                recent_feats.copy(),
                f"{platform}_user_model"
            )

            debug_print(f"{platform} scored user features", scored)

            anomalies = scored[scored["anomaly"] == -1]

            print(f"[DEBUG] {platform} user anomalies found: {len(anomalies)}")

            for entity, row in anomalies.iterrows():
                severity, reason = interpret_user_anomaly(row, platform)

                add_alert_if_new(
                    actions,
                    build_user_alert(
                        platform=platform,
                        entity=entity,
                        row=row,
                        severity=severity,
                        reason=reason,
                        recent_df=recent_all_df
                    )
                )

    print("\n[DEBUG] Processing host model")

    if recent_scoring_df.empty:
        print("[WARN] Skipping host model because recent_scoring_df is empty")
    else:
        baseline_host_feats = build_host_features(baseline_df)
        recent_host_feats = build_host_features(recent_scoring_df)

        debug_print("Baseline host features", baseline_host_feats)
        debug_print("Recent host features", recent_host_feats)

        if not baseline_host_feats.empty and not recent_host_feats.empty:
            host_scored = train_and_score_iforest(
                baseline_host_feats.copy(),
                recent_host_feats.copy(),
                "host_model"
            )

            debug_print("Scored host features", host_scored)

            host_anoms = host_scored[host_scored["anomaly"] == -1]

            print(f"[DEBUG] Host anomalies found: {len(host_anoms)}")

            for host, row in host_anoms.iterrows():
                severity, reason = interpret_host_anomaly(row)

                add_alert_if_new(
                    actions,
                    build_host_alert(
                        host=host,
                        row=row,
                        severity=severity,
                        reason=reason,
                        recent_df=recent_all_df
                    )
                )
        else:
            print("[WARN] Skipping host model due to empty host feature set")

    print("\n[DEBUG] Processing cross-platform Linux + OCI IP correlation")

    linux_ips = expand_ip_set(
        recent_all_df[
            (recent_all_df["platform"] == "linux") &
            (recent_all_df["src_ip"] != "")
        ]["src_ip"]
    )

    oci_ips = expand_ip_set(
        recent_all_df[
            (recent_all_df["platform"] == "oci") &
            (recent_all_df["src_ip"] != "")
        ]["src_ip"]
    )

    debug_print("Recent Linux source IPs", linux_ips)
    debug_print("Recent OCI source IPs", oci_ips)

    shared_ips = linux_ips & oci_ips

    print(f"[DEBUG] Shared Linux/OCI IPs found: {len(shared_ips)}")

    for ip in shared_ips:
        add_alert_if_new(
            actions,
            build_correlation_alert(
                ip=ip,
                recent_df=recent_all_df
            )
        )

    print(f"\n[DEBUG] Total new actions prepared: {len(actions)}")

    if not actions:
        print("[WARN] No new ML or correlation alerts generated")
        print("ML SIDECAR COMPLETE")
        return

    try:
        success, errors = helpers.bulk(
            es_elastic,
            actions,
            chunk_size=50,
            request_timeout=60,
            raise_on_error=False,
            stats_only=False
        )

        print(f"[DEBUG] Bulk create success count: {success}")

        if errors:
            print("[ERROR] Bulk create errors:")
            print(errors)

    except Exception:
        print("[ERROR] Bulk create failed with exception")
        traceback.print_exc()

    print("ML SIDECAR COMPLETE")


if __name__ == "__main__":
    main()
