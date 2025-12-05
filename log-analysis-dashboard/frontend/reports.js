function setupReportHandlers() {
  document.getElementById("generate-report").addEventListener("click", () => {
    document.getElementById("report-modal").style.display = "block";
  });

  document.getElementById("cancel-report").addEventListener("click", () => {
    document.getElementById("report-modal").style.display = "none";
  });

  document
    .getElementById("report-date-range")
    .addEventListener("change", (e) => {
      const customDateContainer = document.getElementById("report-custom-date");
      if (e.target.value === "custom") {
        customDateContainer.classList.remove("hidden");
      } else {
        customDateContainer.classList.add("hidden");
      }
    });

  document.getElementById("report-form").addEventListener("submit", (e) => {
    e.preventDefault();
    generateReport();
  });
}

//  Generate a log analysis report

async function generateReport() {
  const title =
    document.getElementById("report-title").value || "Log Analysis Report";
  const rangeValue = document.getElementById("report-date-range").value;
  let startDate = null;
  let endDate = new Date();
  let dateRangeText = "";

  if (rangeValue === "custom") {
    const fromDate = document.getElementById("report-date-from").value;
    const toDate = document.getElementById("report-date-to").value;
    if (fromDate) startDate = new Date(fromDate);
    if (toDate) endDate = new Date(toDate);
    dateRangeText = `${startDate.toLocaleDateString()} to ${endDate.toLocaleDateString()}`;
  } else {
    const days = parseInt(rangeValue);
    startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    dateRangeText = days === 1 ? "Last 24 hours" : `Last ${days} days`;
  }

  // Filter logs by date
  const filteredLogs = allLogs.filter((log) => {
    const logTime = new Date(log.timestamp);
    return (
      (!startDate || logTime >= startDate) && (!endDate || logTime <= endDate)
    );
  });

  // Determine which report sections to include
  const includeSummary = document.getElementById("include-summary").checked;
  const includeActivity = document.getElementById("include-activity").checked;
  const includeErrors = document.getElementById("include-errors").checked;
  const includeSecurity = document.getElementById("include-security").checked;
  const includeRecommendations = document.getElementById(
    "include-recommendations"
  ).checked;

  // AI Summary + Recommendations
  let aiSummaryText = "";
  let aiRecommendationText = "";

  try {
    if (includeSummary) {
      const summaryPrompt = `Summarize the following system logs and security alerts in 5–7 lines. Provide a concise executive summary suitable for a SOC report.

Logs sample (50 max): ${JSON.stringify(filteredLogs.slice(0, 50))}

Make it sound professional.`;
      aiSummaryText = await callGemini(summaryPrompt);
    }

    if (includeRecommendations) {
      const recommendationPrompt = `Based on these logs and detected alerts, generate 5–7 actionable cybersecurity recommendations. Include improvements for:
- performance
- security hardening
- suspicious activity handling
- brute force / SQLi / anomalies

Logs sample: ${JSON.stringify(filteredLogs.slice(0, 50))}`;
      aiRecommendationText = await callGemini(recommendationPrompt);
    }
  } catch (err) {
    console.error("AI Integration Failed:", err);
    if (includeSummary)
      aiSummaryText =
        "AI summary generation failed. Please check your API configuration.";
    if (includeRecommendations)
      aiRecommendationText =
        "AI recommendations generation failed. Please check your API configuration.";
  }

  let reportContent = generateReportContent(
    title,
    dateRangeText,
    filteredLogs,
    {
      includeSummary,
      includeActivity,
      includeErrors,
      includeSecurity,
      includeRecommendations,
      aiSummaryText,
      aiRecommendationText,
    }
  );

  displayReport(reportContent);
  document.getElementById("report-modal").style.display = "none";
}

function generateReportContent(title, dateRange, logs, options) {
  const totalRequests = logs.length;
  const uniqueIPs = new Set(
    logs.filter((log) => log.ipAddress).map((log) => log.ipAddress)
  ).size;
  const successRequests = logs.filter(
    (log) => log.status >= 200 && log.status < 300
  ).length;
  const clientErrors = logs.filter(
    (log) => log.status >= 400 && log.status < 500
  ).length;
  const serverErrors = logs.filter((log) => log.status >= 500).length;
  const successRate =
    totalRequests > 0
      ? ((successRequests / totalRequests) * 100).toFixed(1)
      : 0;

  // Group by HTTP method
  const methodCounts = {};
  logs.forEach((log) => {
    if (log.method) {
      methodCounts[log.method] = (methodCounts[log.method] || 0) + 1;
    }
  });

  // Most frequent errors
  const errorLogs = logs.filter((log) => log.status >= 400);
  const errorPaths = {};
  errorLogs.forEach((log) => {
    if (log.path) {
      const key = `${log.path} (${log.status})`;
      errorPaths[key] = (errorPaths[key] || 0) + 1;
    }
  });

  // Sort error paths by count
  const topErrors = Object.keys(errorPaths)
    .map((key) => ({ path: key, count: errorPaths[key] }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Security issues
  const securityAlerts = analyzeSecurityIssuesForReport(logs);

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.6;
      color: #333;
      background: #f5f5f5;
      padding: 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      padding: 40px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .header {
      border-bottom: 3px solid #2563eb;
      padding-bottom: 20px;
      margin-bottom: 30px;
    }
    h1 {
      color: #1e40af;
      font-size: 2em;
      margin-bottom: 10px;
    }
    .meta-info {
      color: #666;
      font-size: 0.9em;
    }
    .section {
      margin: 30px 0;
      padding: 20px;
      border-left: 4px solid #3b82f6;
      background: #f8fafc;
    }
    .section h2 {
      color: #1e40af;
      font-size: 1.5em;
      margin-bottom: 15px;
    }
    .section-description {
      color: #64748b;
      margin-bottom: 20px;
      font-size: 0.95em;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    .stat-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .stat-label {
      color: #64748b;
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .stat-value {
      font-size: 2em;
      font-weight: bold;
      color: #1e40af;
      margin: 5px 0;
    }
    .stat-subtitle {
      color: #94a3b8;
      font-size: 0.9em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
      background: white;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #e2e8f0;
    }
    th {
      background: #f1f5f9;
      font-weight: 600;
      color: #475569;
    }
    tr:hover {
      background: #f8fafc;
    }
    .alert-item {
      background: white;
      padding: 15px;
      margin: 10px 0;
      border-radius: 6px;
      border-left: 4px solid #ef4444;
    }
    .alert-item.high {
      border-left-color: #dc2626;
      background: #fef2f2;
    }
    .alert-item.medium {
      border-left-color: #f59e0b;
      background: #fffbeb;
    }
    .alert-item.low {
      border-left-color: #3b82f6;
      background: #eff6ff;
    }
    .alert-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .alert-title {
      font-weight: 600;
      color: #1e293b;
    }
    .severity-badge {
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.75em;
      font-weight: 600;
      text-transform: uppercase;
    }
    .severity-high {
      background: #dc2626;
      color: white;
    }
    .severity-medium {
      background: #f59e0b;
      color: white;
    }
    .severity-low {
      background: #3b82f6;
      color: white;
    }
    .alert-message {
      color: #475569;
      font-size: 0.95em;
      margin-bottom: 5px;
    }
    .alert-time {
      color: #94a3b8;
      font-size: 0.85em;
    }
    .subsection {
      margin: 25px 0;
    }
    .subsection h3 {
      color: #334155;
      font-size: 1.2em;
      margin-bottom: 15px;
    }
    .no-data {
      text-align: center;
      padding: 30px;
      color: #64748b;
      font-style: italic;
    }
    .footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 2px solid #e2e8f0;
      text-align: center;
      color: #64748b;
      font-size: 0.9em;
    }
    @media print {
      body {
        background: white;
        padding: 0;
      }
      .container {
        box-shadow: none;
        padding: 20px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${title}</h1>
      <div class="meta-info">
        <p><strong>Period:</strong> ${dateRange}</p>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Requests</div>
        <div class="stat-value">${totalRequests.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Unique IPs</div>
        <div class="stat-value">${uniqueIPs.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Success Rate</div>
        <div class="stat-value">${successRate}%</div>
        <div class="stat-subtitle">${successRequests.toLocaleString()} successful</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Error Rate</div>
        <div class="stat-value">${(
          ((clientErrors + serverErrors) / totalRequests) *
          100
        ).toFixed(1)}%</div>
        <div class="stat-subtitle">${(
          clientErrors + serverErrors
        ).toLocaleString()} errors</div>
      </div>
    </div>`;

  if (options.includeSummary) {
    html += `
    <div class="section">
      <h2>AI-Generated Executive Summary</h2>
      <div class="section-description">
        ${(options.aiSummaryText || "No AI summary generated").replace(
          /\n/g,
          "<br>"
        )}
      </div>
    </div>`;
  }

  // Activity Trends
  if (options.includeActivity) {
    html += `
    <div class="section">
      <h2>Activity Trends</h2>
      <div class="subsection">
        <h3>HTTP Method Distribution</h3>
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
          </thead>
          <tbody>`;

    Object.keys(methodCounts)
      .sort((a, b) => methodCounts[b] - methodCounts[a])
      .forEach((method) => {
        const count = methodCounts[method];
        const percentage = ((count / totalRequests) * 100).toFixed(1);
        html += `
            <tr>
              <td>${method}</td>
              <td>${count.toLocaleString()}</td>
              <td>${percentage}%</td>
            </tr>`;
      });

    html += `
          </tbody>
        </table>
      </div>
    </div>`;
  }

  // Error Analysis
  if (options.includeErrors) {
    html += `
    <div class="section">
      <h2>Error Analysis</h2>
      <div class="subsection">
        <h3>Error Status Distribution</h3>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">4xx Client Errors</div>
            <div class="stat-value">${clientErrors.toLocaleString()}</div>
            <div class="stat-subtitle">${(
              (clientErrors / totalRequests) *
              100
            ).toFixed(1)}% of total</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">5xx Server Errors</div>
            <div class="stat-value">${serverErrors.toLocaleString()}</div>
            <div class="stat-subtitle">${(
              (serverErrors / totalRequests) *
              100
            ).toFixed(1)}% of total</div>
          </div>
        </div>
      </div>
      <div class="subsection">
        <h3>Top Error Endpoints</h3>`;

    if (topErrors.length > 0) {
      html += `
        <table>
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Count</th>
              <th>Percentage of Errors</th>
            </tr>
          </thead>
          <tbody>`;

      topErrors.forEach((error) => {
        const percentage = ((error.count / errorLogs.length) * 100).toFixed(1);
        html += `
            <tr>
              <td>${error.path}</td>
              <td>${error.count.toLocaleString()}</td>
              <td>${percentage}%</td>
            </tr>`;
      });

      html += `
          </tbody>
        </table>`;
    } else {
      html += `<div class="no-data">No errors were recorded during this period.</div>`;
    }

    html += `
      </div>
    </div>`;
  }

  if (options.includeSecurity) {
    html += `
    <div class="section">
      <h2>Security Analysis</h2>
      <div class="section-description">
        The system detected ${securityAlerts.length} potential security issue${
      securityAlerts.length !== 1 ? "s" : ""
    } during the analyzed period. These findings are ranked by severity and should be investigated further.
      </div>`;

    if (securityAlerts.length > 0) {
      const highAlerts = securityAlerts.filter(
        (alert) => alert.severity === "high"
      );
      const mediumAlerts = securityAlerts.filter(
        (alert) => alert.severity === "medium"
      );
      const lowAlerts = securityAlerts.filter(
        (alert) => alert.severity === "low"
      );

      if (highAlerts.length > 0) {
        html += `
      <div class="subsection">
        <h3>High Severity Issues (${highAlerts.length})</h3>`;

        highAlerts.forEach((alert) => {
          html += `
        <div class="alert-item high">
          <div class="alert-header">
            <div class="alert-title">${alert.title}</div>
            <span class="severity-badge severity-high">High</span>
          </div>
          <div class="alert-message">${alert.message}</div>
          <div class="alert-time">${new Date(
            alert.timestamp
          ).toLocaleString()}</div>
        </div>`;
        });

        html += `
      </div>`;
      }

      if (mediumAlerts.length > 0) {
        html += `
      <div class="subsection">
        <h3>Medium Severity Issues (${mediumAlerts.length})</h3>`;

        mediumAlerts.forEach((alert) => {
          html += `
        <div class="alert-item medium">
          <div class="alert-header">
            <div class="alert-title">${alert.title}</div>
            <span class="severity-badge severity-medium">Medium</span>
          </div>
          <div class="alert-message">${alert.message}</div>
          <div class="alert-time">${new Date(
            alert.timestamp
          ).toLocaleString()}</div>
        </div>`;
        });

        html += `
      </div>`;
      }

      if (lowAlerts.length > 0) {
        html += `
      <div class="subsection">
        <h3>Low Severity Issues (${lowAlerts.length})</h3>`;

        lowAlerts.slice(0, 3).forEach((alert) => {
          html += `
        <div class="alert-item low">
          <div class="alert-header">
            <div class="alert-title">${alert.title}</div>
            <span class="severity-badge severity-low">Low</span>
          </div>
          <div class="alert-message">${alert.message}</div>
          <div class="alert-time">${new Date(
            alert.timestamp
          ).toLocaleString()}</div>
        </div>`;
        });

        if (lowAlerts.length > 3) {
          html += `<div class="no-data">Plus ${
            lowAlerts.length - 3
          } more low severity issue${
            lowAlerts.length - 3 !== 1 ? "s" : ""
          }</div>`;
        }

        html += `
      </div>`;
      }
    } else {
      html += `<div class="no-data">No security issues were detected during this period.</div>`;
    }

    html += `
    </div>`;
  }

  if (options.includeRecommendations) {
    html += `
    <div class="section">
      <h2>AI-Powered Security Recommendations</h2>
      <div class="section-description">
        ${(
          options.aiRecommendationText || "No AI recommendations generated"
        ).replace(/\n/g, "<br>")}
      </div>
    </div>`;
  }

  html += `
    <div class="footer">
      <p>Report generated by Log Analysis Dashboard</p>
    </div>
  </div>
</body>
</html>`;

  return html;
}

// Analyze security issues specifically for the report

function analyzeSecurityIssuesForReport(logs) {
  const ipLogs = {};
  logs.forEach((log) => {
    if (!log.ipAddress) return;

    if (!ipLogs[log.ipAddress]) {
      ipLogs[log.ipAddress] = [];
    }

    ipLogs[log.ipAddress].push(log);
  });

  // Run all security analyses
  const bruteForceAttempts = detectBruteForceAttempts(ipLogs);
  const sqlInjectionAttempts = detectSQLInjection(logs);
  const unusualMethodAttempts = detectUnusualMethods(logs);
  const endpointScanningAttempts = detectEndpointScanning(ipLogs);
  const highErrorRates = detectHighErrorRates(logs);

  // Combine all alerts
  return [
    ...bruteForceAttempts,
    ...sqlInjectionAttempts,
    ...unusualMethodAttempts,
    ...endpointScanningAttempts,
    ...highErrorRates,
  ];
}

/**
 * Generate recommendations based on log analysis
 */
function generateRecommendations(logs, securityAlerts, metrics) {
  const recommendations = [];

  // High server error rate
  if (metrics.errorRate > 0.05) {
    recommendations.push({
      title: "Investigate Server Errors",
      description: `Your system is experiencing a high rate of server errors (${(
        metrics.errorRate * 100
      ).toFixed(1)}%). 
                    Review application logs and monitoring systems to identify the root causes of these 5xx errors. 
                    Consider implementing better error tracking and monitoring.`,
    });
  }

  // High client error rate
  if (metrics.clientErrorRate > 0.15) {
    recommendations.push({
      title: "Address Client Errors",
      description: `Your API is seeing a high rate of client errors (${(
        metrics.clientErrorRate * 100
      ).toFixed(1)}%). 
                    This may indicate issues with API documentation, client implementations, or validation logic. 
                    Consider reviewing your API documentation and client SDKs.`,
    });
  }

  // SQL Injection alerts
  const sqlInjectionAlerts = securityAlerts.filter((alert) =>
    alert.title.includes("SQL Injection")
  );

  if (sqlInjectionAlerts.length > 0) {
    recommendations.push({
      title: "Strengthen Input Validation",
      description: `${sqlInjectionAlerts.length} potential SQL injection attempts were detected. 
                    Review your input validation logic and use parameterized queries. Consider 
                    implementing a Web Application Firewall (WAF) to protect against common attack vectors.`,
    });
  }

  // Brute force attempts
  const bruteForceAlerts = securityAlerts.filter((alert) =>
    alert.title.includes("Brute Force")
  );

  if (bruteForceAlerts.length > 0) {
    recommendations.push({
      title: "Implement Rate Limiting",
      description: `Multiple brute force login attempts were detected. Implement rate limiting, 
                    progressive delays, CAPTCHA, and account lockout policies to protect against 
                    automated login attempts.`,
    });
  }

  // Endpoint scanning
  const scanningAlerts = securityAlerts.filter((alert) =>
    alert.title.includes("Endpoint Scanning")
  );

  if (scanningAlerts.length > 0) {
    recommendations.push({
      title: "Enhance API Security",
      description: `${scanningAlerts.length} instances of potential endpoint scanning were detected. 
                    Consider implementing API throttling, requiring authentication for all endpoints, 
                    and adopting the principle of least privilege for API access.`,
    });
  }

  // Add general recommendations if specific ones weren't triggered
  if (recommendations.length < 3) {
    // General performance recommendation
    recommendations.push({
      title: "Optimize Response Times",
      description: `Consider implementing caching strategies and optimizing database queries to improve 
                    overall system performance. Monitor slow endpoints and set up alerting for performance degradation.`,
    });

    // General security recommendation
    if (!recommendations.some((r) => r.title.includes("API Security"))) {
      recommendations.push({
        title: "Regular Security Audits",
        description: `Implement regular security audits and penetration testing to identify vulnerabilities 
                      before they can be exploited. Keep all libraries and dependencies updated to the latest secure versions.`,
      });
    }

    // General monitoring recommendation
    recommendations.push({
      title: "Enhance Monitoring Coverage",
      description: `Expand your monitoring to include more detailed metrics about API performance, 
                    user behavior, and system health. Set up alerts for unusual patterns that may 
                    indicate security issues or performance problems.`,
    });
  }

  return recommendations;
}

/**
 * Display the generated report in a new window
 */
function displayReport(reportHtml) {
  const reportWindow = window.open("", "_blank");
  reportWindow.document.write(reportHtml);
  reportWindow.document.close();
}
