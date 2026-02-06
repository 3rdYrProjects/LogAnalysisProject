import pandas as pd

def extract_features(logs):
    """
    Input: list of log dictionaries
    Output: pandas DataFrame with ML features
    """

    df = pd.DataFrame(logs)

    if df.empty:
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["minute"] = df["timestamp"].dt.floor("min")

    feature_rows = []

    for (ip, minute), group in df.groupby(["ip", "minute"]):
        total = len(group)

        feature_rows.append({
            "requests_per_min": total,
            "failed_logins": (group["status"] == 401).sum(),
            "unique_endpoints": group["endpoint"].nunique(),
            "method_diversity": group["method"].nunique(),
            "status_4xx_ratio": ((group["status"] >= 400) & (group["status"] < 500)).sum() / total,
            "status_5xx_ratio": (group["status"] >= 500).sum() / total
        })

    return pd.DataFrame(feature_rows)
