/**
 * ml_service.js
 * =============
 * Node.js client that talks to the Python ML API (ml_api.py on port 5001).
 * Used by the upload route and the live log route.
 */

const ML_API = process.env.ML_API_URL || "http://localhost:5001";
const TIMEOUT_MS = 30000; // 30s for large uploads

/**
 * Generic fetch to ML API with timeout
 */
async function mlFetch(path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${ML_API}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "ML API error" }));
      throw new Error(err.error || `ML API returned ${res.status}`);
    }

    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Check if ML API is reachable
 */
async function checkMLHealth() {
  try {
    const res = await fetch(`${ML_API}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    return await res.json();
  } catch {
    return { status: "unreachable", models_loaded: false };
  }
}

/**
 * Analyze a batch of logs (from file upload or DB)
 * @param {Array} logs - Array of log objects
 * @returns {Object} { summary, results }
 */
async function analyzeLogs(logs) {
  return mlFetch("/predict", { logs });
}

/**
 * Analyze a single log in real time (from live agent)
 * @param {Object} log - Single log object
 * @returns {Object} Single prediction result
 */
async function analyzeLogStream(log) {
  return mlFetch("/predict/stream", log);
}

/**
 * Normalize various log file formats into the standard shape
 * that feature_extractor.py expects.
 *
 * Handles:
 *   - MongoDB log format (our own logs)
 *   - JSON log arrays
 *   - Common nginx/apache access log format (parsed line by line)
 *   - CSV logs
 */
function normalizeLogs(rawLogs) {
  return rawLogs.map((log) => ({
    timestamp:
      log.timestamp ||
      log.time ||
      log["@timestamp"] ||
      new Date().toISOString(),
    ip: log.ip || log.ipAddress || log.remote_addr || log.clientIp || "0.0.0.0",
    endpoint: log.endpoint || log.path || log.url || log.request || "/",
    method: log.method || log.verb || log.http_method || "GET",
    status: parseInt(log.status || log.status_code || log.response || 200),
    userAgent: log.userAgent || log.user_agent || log.ua || "",
    details: log.details || log.message || log.msg || "",
    userId: log.userId || log.user_id || log.user || "",
  }));
}

module.exports = {
  analyzeLogs,
  analyzeLogStream,
  checkMLHealth,
  normalizeLogs,
};
