"""
realtime.py
===========
Buffer-based real-time predictor.
The Node.js backend calls process_and_predict() every N seconds,
passing accumulated logs from the live agent.

Usage (from Node.js via child_process or python-shell):
  - Import this module OR call ml_api.py /predict/stream endpoint directly.
  - The REST API approach (ml_api.py) is recommended for production.
"""

import datetime
import joblib
import os
import numpy as np

from feature_extractor import extract_features, MODEL_FEATURE_COLS

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

# ── Load models ───────────────────────────────────────────────────────────────
try:
    iso_model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    rf_model  = joblib.load(os.path.join(MODEL_DIR, "attack_classifier.pkl"))
    scaler    = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    label_enc = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
    READY = True
    print("[realtime] Models loaded successfully.")
except FileNotFoundError:
    READY = False
    print("[realtime] ⚠  Models not found. Run train.py first.")

# ── In-memory log buffer ──────────────────────────────────────────────────────
buffer: list = []


def receive_log(log: dict):
    """Append a single log dict to the in-memory buffer."""
    buffer.append(log)


def process_and_predict() -> list:
    """
    Drain the buffer, run both models, return results.
    Called periodically (e.g. every 10s) by the Node.js backend.
    """
    global buffer

    if not buffer:
        return []

    if not READY:
        return [{"error": "Models not loaded. Run train.py."}]

    logs_to_process = buffer.copy()
    buffer = []

    feat_df = extract_features(logs_to_process)
    if feat_df.empty:
        return []

    X        = feat_df[MODEL_FEATURE_COLS].values
    X_scaled = scaler.transform(X)

    raw_scores = -iso_model.decision_function(X_scaled)
    s_min, s_max = raw_scores.min(), raw_scores.max()
    norm_scores = (raw_scores - s_min) / (s_max - s_min + 1e-9)

    iso_preds    = iso_model.predict(X_scaled)
    rf_preds     = rf_model.predict(X_scaled)
    rf_proba     = rf_model.predict_proba(X_scaled)
    attack_types = label_enc.inverse_transform(rf_preds)

    results = []
    for i, row in feat_df.iterrows():
     for idx, (_, row) in enumerate(feat_df.iterrows()):
        results.append({
            "ip":             row.get("_ip", "unknown"),
            "window":         str(row.get("_minute", "")),
            "anomaly_score":  round(float(norm_scores[idx]), 3),
            "is_anomaly":     bool(iso_preds[idx] == -1),
            "attack_type":    attack_types[idx],
            "attack_confidence": round(float(rf_proba[idx].max()), 3),
            "classification": (
                "Attack Detected" if attack_types[idx] != "Normal"
                else ("Anomalous" if iso_preds[idx] == -1 else "Normal")
            ),
        })

    return results


# ── CLI demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Simulate a brute force attacker
    for _ in range(15):
        receive_log({
            "timestamp": now,
            "ip": "45.83.65.12",
            "endpoint": "/login",
            "method": "POST",
            "status": 401,
            "userAgent": "python-requests/2.28",
            "details": "invalid credentials",
        })

    # Normal user
    receive_log({
        "timestamp": now,
        "ip": "192.168.1.5",
        "endpoint": "/dashboard",
        "method": "GET",
        "status": 200,
        "userAgent": "Mozilla/5.0",
        "details": "",
    })

    results = process_and_predict()
    import json
    print(json.dumps(results, indent=2))