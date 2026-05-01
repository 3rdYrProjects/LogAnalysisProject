"""
ml_api.py
=========
Flask REST API that wraps both ML models.
Node.js backend calls this service for predictions.

Endpoints:
  POST /predict          → Analyze a batch of logs (for log upload)
  POST /predict/stream   → Analyze a single log (for real-time agent)
  GET  /health           → Status check
  GET  /model-info       → Model metadata

Run with:
  python ml_api.py
  (listens on http://localhost:5001)
"""

import os
import json
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd

from feature_extractor import extract_features, MODEL_FEATURE_COLS

app = Flask(__name__)
CORS(app)

# ── Load models ───────────────────────────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

def load_model(name):
    path = os.path.join(MODEL_DIR, name)
    if not os.path.exists(path):
        print(f"[WARN] Model not found: {path}. Run train.py first.")
        return None
    return joblib.load(path)

iso_model    = load_model("isolation_forest.pkl")
rf_model     = load_model("attack_classifier.pkl")
scaler       = load_model("scaler.pkl")
label_enc    = load_model("label_encoder.pkl")

MODELS_READY = all([iso_model, rf_model, scaler, label_enc])

# ── Risk score formula ────────────────────────────────────────────────────────
def compute_risk_score(anomaly_score: float, attack_prob: float, has_payload: bool) -> dict:
    """
    Composite risk score 0–100:
      50% anomaly score
      30% attack classifier probability
      20% payload signal bonus
    """
    payload_bonus = 0.2 if has_payload else 0.0
    raw = (anomaly_score * 0.5) + (attack_prob * 0.3) + (payload_bonus * 0.2)
    score = min(100, round(raw * 100))

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return {"risk_score": score, "risk_level": level}


# ── Main prediction logic ─────────────────────────────────────────────────────
def run_prediction(logs: list) -> list:
    """
    Given raw log dicts, returns one result dict per (ip, minute) window.
    """
    if not MODELS_READY:
        raise RuntimeError("Models not loaded. Run python train.py first.")

    feat_df = extract_features(logs)
    if feat_df.empty:
        return []

    X = feat_df[MODEL_FEATURE_COLS].values
    X_scaled = scaler.transform(X)

    # ── Isolation Forest ──────────────────────────────────────────────────────
    raw_scores  = -iso_model.decision_function(X_scaled)   # higher = more anomalous
    iso_preds   = iso_model.predict(X_scaled)               # -1 = anomaly, 1 = normal

    # Normalize scores to 0-1
    score_min, score_max = raw_scores.min(), raw_scores.max()
    if score_max > score_min:
        norm_scores = (raw_scores - score_min) / (score_max - score_min)
    else:
        norm_scores = np.zeros_like(raw_scores)

    # ── Random Forest ─────────────────────────────────────────────────────────
    rf_preds     = rf_model.predict(X_scaled)
    rf_proba     = rf_model.predict_proba(X_scaled)
    attack_labels = label_enc.inverse_transform(rf_preds)

    results = []
    for i, row in feat_df.iterrows():
     for idx, (_, row) in enumerate(feat_df.iterrows()):

        is_anomaly   = iso_preds[idx] == -1
        anomaly_score = float(round(norm_scores[idx], 3))
        attack_type  = attack_labels[idx]
        attack_conf  = float(round(rf_proba[idx].max(), 3))

        # All class probabilities
        all_probs = {
            label_enc.classes_[j]: round(float(rf_proba[idx][j]), 3)
            for j in range(len(label_enc.classes_))
        }

        has_payload = any([
            row.get("sql_injection_hits", 0) > 0,
            row.get("xss_hits", 0) > 0,
            row.get("traversal_hits", 0) > 0,
            row.get("scanner_agent_hits", 0) > 0,
        ])

        risk = compute_risk_score(anomaly_score, attack_conf, has_payload)

        # Determine final classification
        if attack_type != "Normal":
            classification = "Attack Detected"
        elif is_anomaly:
            classification = "Anomalous Behavior"
        else:
            classification = "Normal"

        # Human-readable explanation
        reasons = []
        if row.get("failed_logins", 0) >= 5:
            reasons.append(f"{int(row['failed_logins'])} failed login attempts")
        if row.get("requests_per_min", 0) >= 50:
            reasons.append(f"High request rate ({int(row['requests_per_min'])}/min)")
        if row.get("unique_endpoints", 0) >= 15:
            reasons.append(f"Scanning {int(row['unique_endpoints'])} unique endpoints")
        if row.get("sql_injection_hits", 0) > 0:
            reasons.append("SQL injection payload detected")
        if row.get("xss_hits", 0) > 0:
            reasons.append("XSS payload detected")
        if row.get("traversal_hits", 0) > 0:
            reasons.append("Path traversal attempt detected")
        if row.get("scanner_agent_hits", 0) > 0:
            reasons.append("Security scanner user agent")
        if row.get("sensitive_path_hits", 0) > 0:
            reasons.append("Access to sensitive/admin path")
        if row.get("is_night_hour", 0):
            reasons.append("Activity during off-hours (night)")

        results.append({
            "ip":             row.get("_ip", "unknown"),
            "window":         str(row.get("_minute", "")),

            # Isolation Forest
            "anomaly_score":  anomaly_score,
            "is_anomaly":     bool(is_anomaly),

            # Attack classifier
            "attack_type":    attack_type,
            "attack_confidence": attack_conf,
            "all_probabilities": all_probs,

            # Risk
            **risk,

            # Summary
            "classification": classification,
            "reasons":        reasons,

            # Raw features (useful for dashboard display)
            "features": {
                "requests_per_min":    int(row.get("requests_per_min", 0)),
                "failed_logins":       int(row.get("failed_logins", 0)),
                "unique_endpoints":    int(row.get("unique_endpoints", 0)),
                "method_diversity":    int(row.get("method_diversity", 0)),
                "status_4xx_ratio":    round(float(row.get("status_4xx_ratio", 0)), 3),
                "status_5xx_ratio":    round(float(row.get("status_5xx_ratio", 0)), 3),
                "sql_injection_hits":  int(row.get("sql_injection_hits", 0)),
                "xss_hits":            int(row.get("xss_hits", 0)),
                "traversal_hits":      int(row.get("traversal_hits", 0)),
                "scanner_agent_hits":  int(row.get("scanner_agent_hits", 0)),
            },
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok" if MODELS_READY else "models_missing",
        "models_loaded": MODELS_READY,
        "models": {
            "isolation_forest": iso_model is not None,
            "attack_classifier": rf_model is not None,
            "scaler": scaler is not None,
            "label_encoder": label_enc is not None,
        }
    })


@app.route("/model-info", methods=["GET"])
def model_info():
    classes = list(label_enc.classes_) if label_enc else []
    return jsonify({
        "attack_classes": classes,
        "feature_columns": MODEL_FEATURE_COLS,
        "models": {
            "anomaly_detection": "Isolation Forest (n_estimators=200, contamination=0.07)",
            "attack_classification": "Random Forest (n_estimators=200, balanced weights)",
        }
    })


@app.route("/predict", methods=["POST"])
def predict_batch():
    """
    Analyze a batch of logs (uploaded file or historical).
    Body: { "logs": [ { ...log fields... }, ... ] }
    """
    try:
        data = request.get_json(force=True)
        logs = data.get("logs", [])

        if not logs:
            return jsonify({"error": "No logs provided"}), 400

        if len(logs) > 50000:
            return jsonify({"error": "Max 50,000 logs per request"}), 400

        results = run_prediction(logs)

        # Summary statistics
        total = len(results)
        attacks    = sum(1 for r in results if r["attack_type"] != "Normal")
        anomalies  = sum(1 for r in results if r["is_anomaly"])
        critical   = sum(1 for r in results if r["risk_level"] == "Critical")
        high       = sum(1 for r in results if r["risk_level"] == "High")

        attack_breakdown = {}
        for r in results:
            at = r["attack_type"]
            attack_breakdown[at] = attack_breakdown.get(at, 0) + 1

        return jsonify({
            "total_windows": total,
            "summary": {
                "attacks_detected":   attacks,
                "anomalies_detected": anomalies,
                "critical_risk":      critical,
                "high_risk":          high,
                "attack_breakdown":   attack_breakdown,
            },
            "results": results,
        })

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


@app.route("/predict/stream", methods=["POST"])
def predict_single():
    """
    Real-time single log analysis (called by the live agent).
    Body: { ...single log fields... }
    """
    try:
        log = request.get_json(force=True)
        results = run_prediction([log])

        if not results:
            return jsonify({"classification": "Normal", "risk_score": 0, "risk_level": "Low"})

        return jsonify(results[0])

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 55)
    print(" CyberLog ML API")
    print(f" Models ready: {MODELS_READY}")
    if not MODELS_READY:
        print(" ⚠  Run: python train.py  to train models first")
    print(" Listening on http://localhost:5001")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5001, debug=False)