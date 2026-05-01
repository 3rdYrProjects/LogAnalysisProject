/**
 * ml_client.js
 * ============
 * Frontend ML integration for CyberLog Dashboard.
 *
 * Replaces rule-based detection in security.js with real ML predictions.
 * Handles:
 *   1. Log file upload → ML analysis → render results
 *   2. Display ML results on the main dashboard (ML Analysis tab)
 *   3. Override renderSecurityAlerts() to use ML results when available
 */

// ── State ─────────────────────────────────────────────────────────────────────
let mlAnalysisResults = null; // Last ML analysis response
let lastUploadedFile = null;

// ── Utility ───────────────────────────────────────────────────────────────────

function riskColor(level) {
  return (
    {
      Critical: "#ef4444",
      High: "#f59e0b",
      Medium: "#3b82f6",
      Low: "#10b981",
    }[level] || "#64748b"
  );
}

function attackIcon(type) {
  return (
    {
      "Brute Force": "fas fa-key",
      "SQL Injection": "fas fa-database",
      XSS: "fas fa-code",
      DoS: "fas fa-bolt",
      "Endpoint Scanning": "fas fa-magnifying-glass",
      "Path Traversal": "fas fa-folder-open",
      Normal: "fas fa-check-circle",
    }[type] || "fas fa-triangle-exclamation"
  );
}

function severityFromRisk(level) {
  return (
    { Critical: "high", High: "high", Medium: "medium", Low: "low" }[level] ||
    "low"
  );
}

// ── Upload + Analyze ──────────────────────────────────────────────────────────

/**
 * Called by the Upload & Analyze button on the landing page / dashboard.
 */
async function uploadLogs() {
  const fileInput = document.getElementById("fileInput");
  if (!fileInput?.files?.length) {
    showUploadStatus("error", "Please select a log file first.");
    return;
  }

  const file = fileInput.files[0];
  lastUploadedFile = file.name;

  showUploadStatus("loading", `Uploading ${file.name}… running ML analysis…`);
  setUploadBtnLoading(true);

  try {
    const formData = new FormData();
    formData.append("logfile", file);

    const token = sessionStorage.getItem("accessToken");
    const res = await fetch(
      `${window.API_BASE || "http://localhost:4000"}/api/upload`,
      {
        method: "POST",
        credentials: "include",
        body: formData,
      },
    );

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Upload failed" }));
      throw new Error(err.error || `Server error ${res.status}`);
    }

    const data = await res.json();
    mlAnalysisResults = data.analysis;

    showUploadStatus(
      "success",
      `Analyzed ${data.parsed.toLocaleString()} logs from "${data.file}"`,
    );

    renderMLResults(data);

    // If we're on the dashboard, also update the security sidebar
    if (typeof renderSecurityAlertsFromML === "function") {
      renderSecurityAlertsFromML(data.analysis.results || []);
    }
  } catch (err) {
    showUploadStatus("error", err.message);
    console.error("[ML Upload]", err);
  } finally {
    setUploadBtnLoading(false);
  }
}

// ── Drag & Drop ───────────────────────────────────────────────────────────────
function initDropZone() {
  const zone = document.getElementById("drop-zone");
  const input = document.getElementById("fileInput");
  if (!zone || !input) return;

  // File input preview
  input.addEventListener("change", () => {
    if (input.files.length) previewFile(input.files[0]);
  });

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("drag-over");
  });

  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));

  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    const files = e.dataTransfer.files;
    if (files.length) {
      input.files = files;
      previewFile(files[0]);
    }
  });
}

function previewFile(file) {
  const reader = new FileReader();
  const preview = document.getElementById("file-preview");
  const content = document.getElementById("preview-content");

  reader.onload = (e) => {
    const text = e.target.result;
    if (preview) preview.style.display = "block";
    if (content)
      content.textContent =
        text.slice(0, 2000) + (text.length > 2000 ? "\n…(truncated)" : "");
  };

  reader.readAsText(file.slice(0, 8192)); // Only read first 8 KB for preview
}

// ── Status messages ───────────────────────────────────────────────────────────
function showUploadStatus(type, message) {
  let box = document.getElementById("upload-status");
  if (!box) {
    box = document.createElement("div");
    box.id = "upload-status";
    box.style.cssText = `
      margin-top: 16px; padding: 12px 16px; border-radius: 8px;
      font-size: 13px; display: flex; align-items: center; gap: 10px;
    `;
    const uploadContainer = document.querySelector(".upload-container");
    if (uploadContainer) uploadContainer.appendChild(box);
  }

  const styles = {
    loading: {
      bg: "rgba(59,130,246,0.1)",
      border: "rgba(59,130,246,0.3)",
      color: "#93c5fd",
      icon: "fas fa-spinner fa-spin",
    },
    success: {
      bg: "rgba(16,185,129,0.1)",
      border: "rgba(16,185,129,0.3)",
      color: "#6ee7b7",
      icon: "fas fa-check-circle",
    },
    error: {
      bg: "rgba(239,68,68,0.1)",
      border: "rgba(239,68,68,0.3)",
      color: "#fca5a5",
      icon: "fas fa-circle-exclamation",
    },
  };

  const s = styles[type] || styles.error;
  box.style.background = s.bg;
  box.style.border = `1px solid ${s.border}`;
  box.style.color = s.color;
  box.innerHTML = `<i class="${s.icon}"></i> ${message}`;
}

function setUploadBtnLoading(loading) {
  const btns = document.querySelectorAll('[onclick="uploadLogs()"]');
  btns.forEach((btn) => {
    btn.disabled = loading;
    btn.innerHTML = loading
      ? '<i class="fas fa-spinner fa-spin"></i> Analyzing…'
      : '<i class="fas fa-magnifying-glass-chart"></i> Upload & Analyze';
  });
}

// ── Render ML Results Panel ───────────────────────────────────────────────────

/**
 * Renders the full ML analysis panel after upload.
 * Inserts a results section below the upload box.
 */
function renderMLResults(data) {
  const { analysis, file, parsed } = data;
  const { summary, results } = analysis;

  let container = document.getElementById("ml-results-panel");
  if (!container) {
    container = document.createElement("div");
    container.id = "ml-results-panel";
    container.style.cssText = "margin-top: 32px;";
    const uploadContainer = document.querySelector(".upload-container");
    if (uploadContainer)
      uploadContainer.parentNode.insertBefore(
        container,
        uploadContainer.nextSibling,
      );
    else document.body.appendChild(container);
  }

  const attackBreakdown = summary.attack_breakdown || {};
  const attackRows = Object.entries(attackBreakdown)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => {
      const isNormal = type === "Normal";
      return `
        <div style="display:flex;align-items:center;justify-content:space-between;
                    padding:10px 14px;border-bottom:1px solid var(--border, #1e3a5a);">
          <div style="display:flex;align-items:center;gap:10px;font-size:13px;">
            <i class="${attackIcon(type)}" style="color:${isNormal ? "#10b981" : "#ef4444"};width:16px;text-align:center;"></i>
            <span>${type}</span>
          </div>
          <span style="font-family:monospace;font-size:12px;
                       padding:2px 8px;border-radius:99px;
                       background:${isNormal ? "rgba(16,185,129,0.1)" : "rgba(239,68,68,0.1)"};
                       color:${isNormal ? "#10b981" : "#ef4444"};">
            ${count} window${count !== 1 ? "s" : ""}
          </span>
        </div>`;
    })
    .join("");

  const topThreats = [...(results || [])]
    .filter((r) => r.classification !== "Normal")
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 20);

  const threatRows = topThreats.length
    ? topThreats
        .map(
          (r) => `
        <div style="display:grid;grid-template-columns:1fr auto auto auto;gap:12px;
                    align-items:center;padding:10px 14px;
                    border-bottom:1px solid var(--border, #1e3a5a);font-size:12px;">
          <div>
            <div style="font-family:monospace;font-weight:600;color:#e2e8f0;">${r.ip}</div>
            <div style="color:#64748b;margin-top:2px;">${r.window}</div>
            ${
              r.reasons?.length
                ? `<div style="color:#64748b;font-size:11px;margin-top:4px;">${r.reasons.slice(0, 2).join(" · ")}</div>`
                : ""
            }
          </div>
          <span style="padding:3px 8px;border-radius:99px;font-weight:700;
                       background:rgba(239,68,68,0.12);color:#f87171;font-size:11px;">
            ${r.attack_type}
          </span>
          <div style="text-align:right;">
            <div style="font-size:16px;font-weight:800;color:${riskColor(r.risk_level)};">${r.risk_score}</div>
            <div style="font-size:10px;color:#64748b;">/ 100</div>
          </div>
          <span style="padding:3px 8px;border-radius:99px;font-size:11px;font-weight:700;
                       background:${riskColor(r.risk_level)}22;color:${riskColor(r.risk_level)};">
            ${r.risk_level}
          </span>
        </div>
      `,
        )
        .join("")
    : `<div style="padding:24px;text-align:center;color:#64748b;">No threats detected 🎉</div>`;

  container.innerHTML = `
    <div style="background:var(--surface, #0b1a2e);border:1px solid var(--border, #1e3a5a);
                border-radius:16px;overflow:hidden;margin-top:24px;">

      <!-- Header -->
      <div style="padding:20px 24px;border-bottom:1px solid var(--border, #1e3a5a);
                  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
        <div>
          <div style="font-size:16px;font-weight:700;">
            <i class="fas fa-brain" style="color:#00e5ff;margin-right:8px;"></i>
            ML Analysis Results
          </div>
          <div style="font-size:12px;color:#64748b;margin-top:4px;font-family:monospace;">
            ${file} · ${parsed.toLocaleString()} logs analyzed
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          ${metricPill("Attacks", summary.attacks_detected, "#ef4444")}
          ${metricPill("Anomalies", summary.anomalies_detected, "#f59e0b")}
          ${metricPill("Critical", summary.critical_risk, "#ef4444")}
          ${metricPill("High Risk", summary.high_risk, "#f59e0b")}
        </div>
      </div>

      <!-- Two-column layout -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0;">

        <!-- Attack Breakdown -->
        <div style="border-right:1px solid var(--border, #1e3a5a);">
          <div style="padding:14px 16px;font-size:11px;font-family:monospace;
                      color:#64748b;text-transform:uppercase;letter-spacing:0.08em;
                      border-bottom:1px solid var(--border, #1e3a5a);">
            Attack Type Breakdown
          </div>
          ${attackRows}
        </div>

        <!-- Top Threats -->
        <div>
          <div style="padding:14px 16px;font-size:11px;font-family:monospace;
                      color:#64748b;text-transform:uppercase;letter-spacing:0.08em;
                      border-bottom:1px solid var(--border, #1e3a5a);">
            Top Threat IPs (by Risk Score)
          </div>
          ${threatRows}
        </div>
      </div>
    </div>
  `;
}

function metricPill(label, value, color) {
  return `
    <div style="padding:8px 14px;border-radius:8px;
                background:${color}12;border:1px solid ${color}30;text-align:center;">
      <div style="font-size:20px;font-weight:800;color:${color};">${value || 0}</div>
      <div style="font-size:10px;color:#64748b;font-family:monospace;">${label}</div>
    </div>`;
}

// ── Integrate with Dashboard Security Sidebar ─────────────────────────────────

/**
 * Convert ML results into the alert format used by security.js / renderSecurityAlerts()
 * Called after upload so the sidebar stays in sync.
 */
function renderSecurityAlertsFromML(results) {
  const alerts = results
    .filter((r) => r.classification !== "Normal")
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)
    .map((r) => ({
      title: `[ML] ${r.attack_type}`,
      message: r.reasons?.join(". ") || `Suspicious activity from IP ${r.ip}`,
      severity: severityFromRisk(r.risk_level),
      timestamp: new Date(r.window || Date.now()),
      ip: r.ip,
    }));

  if (typeof renderSecurityAlerts === "function") {
    renderSecurityAlerts(alerts);
  }

  // Update security issues count
  const secEl = document.getElementById("security-issues");
  if (secEl) secEl.textContent = alerts.length;
}

// ── ML Health Check Badge ─────────────────────────────────────────────────────
async function checkAndShowMLStatus() {
  try {
    const token = sessionStorage.getItem("accessToken");
    const res = await fetch(
      `${window.API_BASE || "http://localhost:4000"}/api/ml-health`,
      {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: "include",
      },
    );
    const data = await res.json();

    const indicator = document.getElementById("ml-status-indicator");
    if (!indicator) return;

    if (data.models_loaded) {
      indicator.innerHTML = `<i class="fas fa-circle" style="color:#10b981;font-size:8px;"></i> ML Active`;
      indicator.style.color = "#10b981";
    } else {
      indicator.innerHTML = `<i class="fas fa-circle" style="color:#ef4444;font-size:8px;"></i> ML Offline`;
      indicator.style.color = "#ef4444";
    }
  } catch {
    const indicator = document.getElementById("ml-status-indicator");
    if (indicator) {
      indicator.innerHTML = `<i class="fas fa-circle" style="color:#ef4444;font-size:8px;"></i> ML Offline`;
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initDropZone();
  checkAndShowMLStatus();
});
