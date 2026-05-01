"""
feature_extractor.py
====================
Extracts per-IP-per-minute features from raw log dictionaries.
Handles missing fields gracefully so it works on real-world messy logs.
"""

import re
import pandas as pd
import numpy as np


# ── SQL Injection patterns ───────────────────────────────────────────────────
SQL_PATTERNS = re.compile(
    r"(union\s+select|select\s+.+from|drop\s+table|insert\s+into|"
    r"update\s+.+set|delete\s+from|exec\s*\(|execute\s*\(|"
    r"'\s*or\s*'?1'?\s*=\s*'?1|'\s*or\s+1\s*=\s*1|--\s|/\*|\*/|"
    r"xp_cmdshell|sp_executesql|char\s*\(|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)

# ── XSS patterns ─────────────────────────────────────────────────────────────
XSS_PATTERNS = re.compile(
    r"(<script|</script|javascript:|onerror\s*=|onload\s*=|"
    r"alert\s*\(|document\.cookie|<iframe|<img\s+src\s*=|"
    r"eval\s*\(|String\.fromCharCode)",
    re.IGNORECASE,
)

# ── Path Traversal patterns ───────────────────────────────────────────────────
TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/etc/shadow|"
    r"c:\\windows|cmd\.exe|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)

# ── Suspicious user agents ────────────────────────────────────────────────────
SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|nuclei|dirbuster|gobuster|wpscan|"
    r"hydra|medusa|burpsuite|masscan|zgrab|python-requests/|"
    r"curl/|wget/|scrapy|go-http-client)",
    re.IGNORECASE,
)

# ── Sensitive endpoints that should rarely be hit ────────────────────────────
SENSITIVE_PATHS = {
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
    "/backup", "/.git", "/shell", "/cmd", "/exec", "/eval",
    "/proc/self", "/etc/passwd", "/web.config", "/server-status",
    "/.htaccess", "/xmlrpc.php",
}


def _safe_str(val) -> str:
    return str(val) if val is not None else ""


def _check_payload(log: dict) -> dict:
    """Scan all string fields in a log for attack signatures."""
    combined = " ".join([
        _safe_str(log.get("path", "")),
        _safe_str(log.get("endpoint", "")),
        _safe_str(log.get("details", "")),
        _safe_str(log.get("message", "")),
        _safe_str(log.get("activity", "")),
        _safe_str(log.get("userAgent", "")),
    ])
    return {
        "has_sql":       int(bool(SQL_PATTERNS.search(combined))),
        "has_xss":       int(bool(XSS_PATTERNS.search(combined))),
        "has_traversal": int(bool(TRAVERSAL_PATTERNS.search(combined))),
        "has_scanner":   int(bool(SCANNER_AGENTS.search(combined))),
        "has_sensitive_path": int(
            any(sp in _safe_str(log.get("path", log.get("endpoint", ""))).lower()
                for sp in SENSITIVE_PATHS)
        ),
    }


def extract_features(logs: list) -> pd.DataFrame:
    """
    Input : list of log dicts (from MongoDB or uploaded file)
    Output: DataFrame of features — one row per (ip, minute) window

    Columns returned:
        requests_per_min, failed_logins, unique_endpoints,
        method_diversity, status_4xx_ratio, status_5xx_ratio,
        sql_injection_hits, xss_hits, traversal_hits,
        scanner_agent_hits, sensitive_path_hits,
        hour_of_day, is_night_hour
    """
    if not logs:
        return pd.DataFrame()

    df = pd.DataFrame(logs)

    # ── Normalize field names (MongoDB vs uploaded files may differ) ─────────
    if "ipAddress" in df.columns and "ip" not in df.columns:
        df["ip"] = df["ipAddress"]
    if "ip" not in df.columns:
        df["ip"] = "0.0.0.0"

    if "path" in df.columns and "endpoint" not in df.columns:
        df["endpoint"] = df["path"]
    if "endpoint" not in df.columns:
        df["endpoint"] = "/"

    if "method" not in df.columns:
        df["method"] = "GET"

    if "status" not in df.columns:
        df["status"] = 200
    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(200).astype(int)

    # ── Timestamp ─────────────────────────────────────────────────────────────
    df["timestamp"] = pd.to_datetime(df.get("timestamp", pd.Timestamp.now()), errors="coerce")
    df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.now())
    df["minute"] = df["timestamp"].dt.floor("min")
    df["hour"]   = df["timestamp"].dt.hour

    # ── Per-row attack signal flags ───────────────────────────────────────────
    signals = df.to_dict("records")
    flag_df = pd.DataFrame([_check_payload(r) for r in signals])
    df = pd.concat([df.reset_index(drop=True), flag_df], axis=1)

    # ── Aggregate per (ip, minute) ────────────────────────────────────────────
    feature_rows = []

    for (ip, minute), grp in df.groupby(["ip", "minute"]):
        total = len(grp)

        failed = int(
            ((grp["status"] == 401) | (grp["status"] == 403)).sum()
        )

        feature_rows.append({
            # Volume / frequency
            "requests_per_min":    total,
            "failed_logins":       failed,
            "unique_endpoints":    grp["endpoint"].nunique(),
            "method_diversity":    grp["method"].nunique(),

            # Status code ratios
            "status_4xx_ratio":    (
                ((grp["status"] >= 400) & (grp["status"] < 500)).sum() / total
            ),
            "status_5xx_ratio":    (grp["status"] >= 500).sum() / total,

            # Attack payload signals
            "sql_injection_hits":  int(grp["has_sql"].sum()),
            "xss_hits":            int(grp["has_xss"].sum()),
            "traversal_hits":      int(grp["has_traversal"].sum()),
            "scanner_agent_hits":  int(grp["has_scanner"].sum()),
            "sensitive_path_hits": int(grp["has_sensitive_path"].sum()),

            # Time features
            "hour_of_day":         int(grp["hour"].iloc[0]),
            "is_night_hour":       int(grp["hour"].iloc[0] < 6 or grp["hour"].iloc[0] >= 22),

            # Metadata (not used in model but needed for output)
            "_ip":     ip,
            "_minute": str(minute),
        })

    return pd.DataFrame(feature_rows)


MODEL_FEATURE_COLS = [
    "requests_per_min",
    "failed_logins",
    "unique_endpoints",
    "method_diversity",
    "status_4xx_ratio",
    "status_5xx_ratio",
    "sql_injection_hits",
    "xss_hits",
    "traversal_hits",
    "scanner_agent_hits",
    "sensitive_path_hits",
    "hour_of_day",
    "is_night_hour"
]