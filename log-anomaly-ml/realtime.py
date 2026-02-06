import datetime
import joblib
from feature_extractor import extract_features

model = joblib.load("isolation_forest.pkl")
buffer = []

def receive_log(log):
    buffer.append(log)

def process_and_predict():
    global buffer

    if not buffer:
        return []

    features = extract_features(buffer)
    buffer = []

    scores = -model.decision_function(features)
    preds = model.predict(features)

    results = []
    for i in range(len(features)):
        results.append({
            "anomaly_score": round(scores[i], 2),
            "classification": "Anomalous" if preds[i] == -1 else "Normal"
        })

    return results

# ---- DEMO ----
if __name__ == "__main__":
    receive_log({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": "192.168.1.9",
        "endpoint": "/login",
        "method": "POST",
        "status": 401
    })

    receive_log({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": "192.168.1.9",
        "endpoint": "/login",
        "method": "POST",
        "status": 401
    })

    print(process_and_predict())
