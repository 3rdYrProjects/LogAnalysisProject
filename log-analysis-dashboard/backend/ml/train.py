"""
train.py
========
Trains two models:
  1. IsolationForest  → anomaly detection (unsupervised)
  2. RandomForestClassifier → attack classification (supervised)

Saves:
  - models/isolation_forest.pkl
  - models/attack_classifier.pkl
  - models/scaler.pkl
  - models/label_encoder.pkl
"""

import os
import random
import datetime
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from feature_extractor import extract_features, MODEL_FEATURE_COLS

os.makedirs("models", exist_ok=True)

random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────────────────────────────────────
# 1.  SYNTHETIC LOG GENERATION
# ─────────────────────────────────────────────────────────────────────────────

ENDPOINTS = [
    "/home", "/login", "/dashboard", "/profile", "/api/users",
    "/api/data", "/logout", "/register", "/api/orders", "/api/products",
]

SENSITIVE = [
    "/admin", "/wp-admin", "/.env", "/phpmyadmin", "/backup",
    "/.git", "/shell", "/etc/passwd",
]

SQL_PAYLOADS = [
    "/login?id=1' OR '1'='1",
    "/search?q=1 UNION SELECT * FROM users",
    "/api?cmd=DROP TABLE users--",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/profile?name=<img onerror=alert(1) src=x>",
]

SCANNER_UAS = [
    "sqlmap/1.7", "Nikto/2.1.6", "DirBuster-1.0",
    "python-requests/2.28", "Nmap Scripting Engine",
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Chrome/120.0.0.0 Safari/537.36",
]


def ts(offset_minutes=0):
    base = datetime.datetime(2024, 6, 15, 10, 0, 0)
    return (base + datetime.timedelta(minutes=offset_minutes)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def make_normal_logs(n=4000):
    logs = []
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 20),
            "ip": f"192.168.1.{random.randint(1, 50)}",
            "endpoint": random.choice(ENDPOINTS),
            "method": random.choices(["GET", "POST"], weights=[70, 30])[0],
            "status": random.choices(
                [200, 201, 204, 301, 302, 400, 401, 404, 500],
                weights=[60, 5, 3, 5, 3, 5, 5, 10, 4],
            )[0],
            "userAgent": random.choice(NORMAL_UAS),
            "details": "",
        })
    return logs, ["Normal"] * len(logs)


def make_brute_force_logs(n=600):
    """Same IP hammering /login with 401s"""
    logs, labels = [], []
    attacker_ips = [f"45.83.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(6)]
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 30),
            "ip": random.choice(attacker_ips),
            "endpoint": "/login",
            "method": "POST",
            "status": random.choices([401, 403], weights=[85, 15])[0],
            "userAgent": random.choice(NORMAL_UAS),
            "details": "invalid credentials",
        })
        labels.append("Brute Force")
    return logs, labels


def make_sql_injection_logs(n=300):
    logs, labels = [], []
    attacker_ips = [f"203.0.113.{random.randint(1,50)}" for _ in range(4)]
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 10),
            "ip": random.choice(attacker_ips),
            "endpoint": random.choice(SQL_PAYLOADS),
            "method": random.choices(["GET", "POST"], weights=[60, 40])[0],
            "status": random.choices([200, 500, 400], weights=[40, 40, 20])[0],
            "userAgent": random.choice(SCANNER_UAS),
            "details": random.choice(SQL_PAYLOADS),
        })
        labels.append("SQL Injection")
    return logs, labels


def make_xss_logs(n=200):
    logs, labels = [], []
    attacker_ips = [f"198.51.100.{random.randint(1,30)}" for _ in range(3)]
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 15),
            "ip": random.choice(attacker_ips),
            "endpoint": random.choice(XSS_PAYLOADS),
            "method": "GET",
            "status": random.choices([200, 400], weights=[70, 30])[0],
            "userAgent": random.choice(NORMAL_UAS + SCANNER_UAS),
            "details": random.choice(XSS_PAYLOADS),
        })
        labels.append("XSS")
    return logs, labels


def make_dos_logs(n=500):
    """Single IP flood — very high requests per minute"""
    logs, labels = [], []
    attacker = f"77.88.{random.randint(1,254)}.{random.randint(1,254)}"
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 80),   # 80 req in same minute → DoS
            "ip": attacker,
            "endpoint": random.choice(ENDPOINTS),
            "method": "GET",
            "status": random.choices([200, 429, 503], weights=[40, 40, 20])[0],
            "userAgent": random.choice(NORMAL_UAS),
            "details": "",
        })
        labels.append("DoS")
    return logs, labels


def make_scanner_logs(n=250):
    logs, labels = [], []
    attacker_ips = [f"185.220.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(3)]
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 5),
            "ip": random.choice(attacker_ips),
            "endpoint": random.choice(SENSITIVE + ENDPOINTS),
            "method": random.choice(["GET", "HEAD", "OPTIONS"]),
            "status": random.choices([404, 403, 200], weights=[60, 25, 15])[0],
            "userAgent": random.choice(SCANNER_UAS),
            "details": "",
        })
        labels.append("Endpoint Scanning")
    return logs, labels


def make_path_traversal_logs(n=150):
    traversal_paths = [
        "/download?file=../../etc/passwd",
        "/img?src=../../../../windows/system32/cmd.exe",
        "/read?path=%2e%2e%2f%2e%2e%2fetc%2fshadow",
    ]
    logs, labels = [], []
    attacker_ips = [f"91.108.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(3)]
    for i in range(n):
        logs.append({
            "timestamp": ts(i // 10),
            "ip": random.choice(attacker_ips),
            "endpoint": random.choice(traversal_paths),
            "method": "GET",
            "status": random.choices([403, 404, 500, 200], weights=[40, 30, 20, 10])[0],
            "userAgent": random.choice(SCANNER_UAS + NORMAL_UAS),
            "details": random.choice(traversal_paths),
        })
        labels.append("Path Traversal")
    return logs, labels


# ─────────────────────────────────────────────────────────────────────────────
# 2.  ASSEMBLE DATASET
# ─────────────────────────────────────────────────────────────────────────────

print("Generating synthetic training logs...")

all_logs, all_labels = [], []
for gen_fn in [
    make_normal_logs,
    make_brute_force_logs,
    make_sql_injection_logs,
    make_xss_logs,
    make_dos_logs,
    make_scanner_logs,
    make_path_traversal_logs,
]:
    logs, labels = gen_fn()
    all_logs.extend(logs)
    all_labels.extend(labels)

print(f"Total raw logs: {len(all_logs)}")

# ─────────────────────────────────────────────────────────────────────────────
# 3.  FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

print("Extracting features...")
feat_df = extract_features(all_logs)

print(f"Feature rows (per-IP-minute windows): {len(feat_df)}")

X = feat_df[MODEL_FEATURE_COLS].values

# ─────────────────────────────────────────────────────────────────────────────
# 4.  SCALER  (fit on all data — used by both models)
# ─────────────────────────────────────────────────────────────────────────────

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, "models/scaler.pkl")
print("Scaler saved.")

# ─────────────────────────────────────────────────────────────────────────────
# 5.  ISOLATION FOREST  (anomaly detection — unsupervised)
# ─────────────────────────────────────────────────────────────────────────────

print("\nTraining Isolation Forest...")

# Fit ONLY on normal-looking windows (lower contamination for cleaner baseline)
iso = IsolationForest(
    n_estimators=200,
    contamination=0.07,   # expect ~7% anomalies in real traffic
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
iso.fit(X_scaled)
joblib.dump(iso, "models/isolation_forest.pkl")

preds = iso.predict(X_scaled)
n_anomalies = (preds == -1).sum()
print(f"Isolation Forest trained. Flagged {n_anomalies}/{len(X_scaled)} windows as anomalous.")

# ─────────────────────────────────────────────────────────────────────────────
# 6.  ATTACK CLASSIFIER  (supervised — Random Forest)
# ─────────────────────────────────────────────────────────────────────────────

print("\nBuilding labeled dataset for attack classifier...")

# We need per-window labels. Strategy: majority vote of raw log labels
# that fall into each (ip, minute) group.
# We store the raw logs alongside their labels, then re-group.

logs_with_labels = []
for log, label in zip(all_logs, all_labels):
    logs_with_labels.append({**log, "_label": label})

label_df = pd.DataFrame(logs_with_labels)
label_df["timestamp"] = pd.to_datetime(label_df["timestamp"], errors="coerce")
label_df["minute"] = label_df["timestamp"].dt.floor("min")

if "ipAddress" in label_df.columns and "ip" not in label_df.columns:
    label_df["ip"] = label_df["ipAddress"]

# Majority-vote label per (ip, minute)
window_labels = (
    label_df.groupby(["ip", "minute"])["_label"]
    .agg(lambda x: x.mode()[0])
    .reset_index()
    .rename(columns={"_label": "window_label"})
)

# Merge with features
feat_df["_ip"] = feat_df["_ip"]
feat_df["_minute"] = pd.to_datetime(feat_df["_minute"]).dt.floor("min")
feat_df = feat_df.merge(
    window_labels,
    left_on=["_ip", "_minute"],
    right_on=["ip", "minute"],
    how="left",
)
feat_df["window_label"] = feat_df["window_label"].fillna("Normal")

print("Label distribution:")
print(feat_df["window_label"].value_counts())

le = LabelEncoder()
y = le.fit_transform(feat_df["window_label"])
joblib.dump(le, "models/label_encoder.pkl")
print(f"\nClasses: {list(le.classes_)}")

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTraining Random Forest Classifier...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=4,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
rf.fit(X_train, y_train)
joblib.dump(rf, "models/attack_classifier.pkl")

# ── Evaluation ──────────────────────────────────────────────────────────────
y_pred = rf.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print("\n✅ All models saved to ./models/")
print("   - models/isolation_forest.pkl")
print("   - models/attack_classifier.pkl")
print("   - models/scaler.pkl")
print("   - models/label_encoder.pkl")