import random
import datetime
import joblib
from sklearn.ensemble import IsolationForest
from feature_extractor import extract_features

def generate_logs(n=5000):
    logs = []
    for _ in range(n):
        logs.append({
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": f"192.168.1.{random.randint(1, 20)}",
            "endpoint": random.choice(
                ["/home", "/login", "/dashboard", "/profile"]
            ),
            "method": random.choice(["GET", "POST"]),
            "status": random.choices(
                [200, 401, 403, 500],
                weights=[80, 10, 7, 3]
            )[0]
        })
    return logs

# Generate baseline logs
logs = generate_logs()

# Extract features
X = extract_features(logs)

# Train Isolation Forest
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(X)

# Save model
joblib.dump(model, "isolation_forest.pkl")

print("Model trained and saved successfully")
