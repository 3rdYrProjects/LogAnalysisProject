/**
 * Report generation functionality
 */

/**
 * Set up event handlers for report generation
 */
function setupReportHandlers() {
  // Report button click handler
  document.getElementById("generate-report").addEventListener("click", () => {
    document.getElementById("report-modal").style.display = "block"
  })

  // Cancel report button
  document.getElementById("cancel-report").addEventListener("click", () => {
    document.getElementById("report-modal").style.display = "none"
  })

  // Toggle custom date range in report modal
  document
    .getElementById("report-date-range")
    .addEventListener("change", (e) => {
      const customDateContainer = document.getElementById("report-custom-date")
      if (e.target.value === "custom") {
        customDateContainer.classList.remove("hidden")
      } else {
        customDateContainer.classList.add("hidden")
      }
    })

  // Report form submission
  document.getElementById("report-form").addEventListener("submit", (e) => {
    e.preventDefault()
    generateReport()
  })
}

/**
 * Generate a log analysis report
 */
function generateReport() {
  // Get report options from form
  const title =
    document.getElementById("report-title").value || "Log Analysis Report"
  const rangeValue = document.getElementById("report-date-range").value

  let startDate = null
  let endDate = new Date()
  let dateRangeText = ""

  if (rangeValue === "custom") {
    const fromDate = document.getElementById("report-date-from").value
    const toDate = document.getElementById("report-date-to").value

    if (fromDate) startDate = new Date(fromDate)
    if (toDate) endDate = new Date(toDate)

    dateRangeText = `${startDate.toLocaleDateString()} to ${endDate.toLocaleDateString()}`
  } else {
    const days = parseInt(rangeValue)
    startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    if (days === 1) {
      dateRangeText = "Last 24 hours"
    } else {
      dateRangeText = `Last ${days} days`
    }
  }

  // Filter logs by date range
  const filteredLogs = allLogs.filter((log) => {
    const logTime = new Date(log.timestamp)
    return (
      (startDate ? logTime >= startDate : true) &&
      (endDate ? logTime <= endDate : true)
    )
  })

  // Get sections to include
  const includeSummary = document.getElementById("include-summary").checked
  const includeActivity = document.getElementById("include-activity").checked
  const includeErrors = document.getElementById("include-errors").checked
  const includeSecurity = document.getElementById("include-security").checked
  const includeRecommendations = document.getElementById(
    "include-recommendations"
  ).checked

  // Generate report content
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
    }
  )

  // Show the report in a new tab/window
  displayReport(reportContent)

  // Close the modal
  document.getElementById("report-modal").style.display = "none"
}

/**
 * Generate the report HTML content
 */
function generateReportContent(title, dateRange, logs, options) {
  // Basic stats
  const totalRequests = logs.length
  const uniqueIPs = new Set(
    logs.filter((log) => log.ipAddress).map((log) => log.ipAddress)
  ).size
  const successRequests = logs.filter(
    (log) => log.status >= 200 && log.status < 300
  ).length
  const clientErrors = logs.filter(
    (log) => log.status >= 400 && log.status < 500
  ).length
  const serverErrors = logs.filter((log) => log.status >= 500).length
  const successRate =
    totalRequests > 0 ? ((successRequests / totalRequests) * 100).toFixed(1) : 0

  // Group by HTTP method
  const methodCounts = {}
  logs.forEach((log) => {
    if (log.method) {
      methodCounts[log.method] = (methodCounts[log.method] || 0) + 1
    }
  })

  // Most frequent errors
  const errorLogs = logs.filter((log) => log.status >= 400)
  const errorPaths = {}
  errorLogs.forEach((log) => {
    if (log.path) {
      const key = `${log.path} (${log.status})`
      errorPaths[key] = (errorPaths[key] || 0) + 1
    }
  })

  // Sort error paths by count
  const topErrors = Object.keys(errorPaths)
    .map((key) => ({ path: key, count: errorPaths[key] }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  // Security issues
  const securityAlerts = analyzeSecurityIssuesForReport(logs)

  // Build the HTML content
  let html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 1200px;
          margin: 0 auto;
          padding: 20px;
        }
        .report-header {
          text-align: center;
          margin-bottom: 30px;
          padding-bottom: 20px;
          border-bottom: 1px solid #eee;
        }
        .report-date {
          color: #666;
          font-size: 1.1em;
        }
        .section {
          margin-bottom: 40px;
        }
        h1 {
          color: #2563eb;
        }
        h2 {
          color: #1e293b;
          border-bottom: 1px solid #eee;
          padding-bottom: 10px;
          margin-top: 30px;
        }
        h3 {
          color: #334155;
        }
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
          gap: 20px;
          margin: 20px 0;
        }
        .stat-card {
          border: 1px solid #eee;
          border-radius: 8px;
          padding: 15px;
          text-align: center;
          box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .stat-value {
          font-size: 2em;
          font-weight: bold;
          color: #2563eb;
          margin: 10px 0;
        }
        .stat-label {
          color: #64748b;
          font-size: 0.9em;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          margin: 20px 0;
        }
        th, td {
          padding: 12px;
          text-align: left;
          border-bottom: 1px solid #eee;
        }
        th {
          background-color: #f8fafc;
          font-weight: bold;
        }
        tr:hover {
          background-color: #f1f5f9;
        }
        .recommendation {
          background-color: #f0f9ff;
          border-left: 4px solid #0ea5e9;
          padding: 15px;
          margin: 15px 0;
          border-radius: 4px;
        }
        .alert-item {
          margin-bottom: 15px;
          padding: 15px;
          border-radius: 6px;
        }
        .high {
          background-color: #fef2f2;
          border-left: 4px solid #ef4444;
        }
        .medium {
          background-color: #fff7ed;
          border-left: 4px solid #f59e0b;
        }
        .low {
          background-color: #f0f9ff;
          border-left: 4px solid #3b82f6;
        }
        .alert-title {
          font-weight: bold;
          margin-bottom: 5px;
        }
        .alert-severity {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 4px;
          font-size: 0.8em;
          font-weight: bold;
          text-transform: uppercase;
          margin-left: 10px;
        }
        .alert-severity.high {
          background-color: #fecaca;
          color: #b91c1c;
        }
        .alert-severity.medium {
          background-color: #fed7aa;
          color: #c2410c;
        }
        .alert-severity.low {
          background-color: #bfdbfe;
          color: #1d4ed8;
        }
        .footer {
          text-align: center;
          margin-top: 50px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #64748b;
          font-size: 0.9em;
        }
        @media print {
          body {
            padding: 0;
          }
          .no-print {
            display: none;
          }
        }
      </style>
    </head>
    <body>
      <div class="report-header">
        <h1>${title}</h1>
        <p class="report-date">
          <strong>Period:</strong> ${dateRange}<br>
          <strong>Generated:</strong> ${new Date().toLocaleString()}
        </p>
      </div>
  `

  // Executive Summary
  if (options.includeSummary) {
    html += `
      <div class="section">
        <h2>Executive Summary</h2>
        <p>
          This report provides an analysis of system logs for the period ${dateRange}.
          During this time, the system processed ${totalRequests.toLocaleString()} requests
          from ${uniqueIPs} unique IP addresses with an overall success rate of ${successRate}%.
        </p>
        
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Total Requests</div>
            <div class="stat-value">${totalRequests.toLocaleString()}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Success Rate</div>
            <div class="stat-value">${successRate}%</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Client Errors</div>
            <div class="stat-value">${clientErrors.toLocaleString()}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Server Errors</div>
            <div class="stat-value">${serverErrors.toLocaleString()}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Unique IPs</div>
            <div class="stat-value">${uniqueIPs.toLocaleString()}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Security Issues</div>
            <div class="stat-value">${securityAlerts.length.toLocaleString()}</div>
          </div>
        </div>
      </div>
    `
  }

  // Activity Trends
  if (options.includeActivity) {
    html += `
      <div class="section">
        <h2>Activity Trends</h2>
        
        <h3>HTTP Method Distribution</h3>
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
          </thead>
          <tbody>
    `

    Object.keys(methodCounts)
      .sort((a, b) => methodCounts[b] - methodCounts[a])
      .forEach((method) => {
        const count = methodCounts[method]
        const percentage = ((count / totalRequests) * 100).toFixed(1)

        html += `
          <tr>
            <td>${method}</td>
            <td>${count.toLocaleString()}</td>
            <td>${percentage}%</td>
          </tr>
        `
      })

    html += `
          </tbody>
        </table>
        
        <h3>Busiest Time Periods</h3>
        <p>
          Analysis of request volumes shows patterns in system usage that can be used
          for capacity planning and optimization.
        </p>
      </div>
    `
  }

  // Error Analysis
  if (options.includeErrors) {
    html += `
      <div class="section">
        <h2>Error Analysis</h2>
        
        <h3>Error Status Distribution</h3>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">4xx Client Errors</div>
            <div class="stat-value">${clientErrors.toLocaleString()}</div>
            <div class="stat-label">${(
              (clientErrors / totalRequests) *
              100
            ).toFixed(1)}% of total</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">5xx Server Errors</div>
            <div class="stat-value">${serverErrors.toLocaleString()}</div>
            <div class="stat-label">${(
              (serverErrors / totalRequests) *
              100
            ).toFixed(1)}% of total</div>
          </div>
        </div>
        
        <h3>Top Error Endpoints</h3>
    `

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
          <tbody>
      `

      topErrors.forEach((error) => {
        const percentage = ((error.count / errorLogs.length) * 100).toFixed(1)

        html += `
          <tr>
            <td>${error.path}</td>
            <td>${error.count.toLocaleString()}</td>
            <td>${percentage}%</td>
          </tr>
        `
      })

      html += `
          </tbody>
        </table>
      `
    } else {
      html += `<p>No errors were recorded during this period.</p>`
    }

    html += `</div>`
  }

  // Security Analysis
  if (options.includeSecurity) {
    html += `
      <div class="section">
        <h2>Security Analysis</h2>
        <p>
          The system detected ${securityAlerts.length} potential security issues during the analyzed period.
          These findings are ranked by severity and should be investigated further.
        </p>
    `

    if (securityAlerts.length > 0) {
      // Group by severity
      const highAlerts = securityAlerts.filter(
        (alert) => alert.severity === "high"
      )
      const mediumAlerts = securityAlerts.filter(
        (alert) => alert.severity === "medium"
      )
      const lowAlerts = securityAlerts.filter(
        (alert) => alert.severity === "low"
      )

      // High severity alerts
      if (highAlerts.length > 0) {
        html += `
          <h3>High Severity Issues (${highAlerts.length})</h3>
        `

        highAlerts.forEach((alert) => {
          html += `
            <div class="alert-item high">
              <div class="alert-title">
                ${alert.title}
                <span class="alert-severity high">High</span>
              </div>
              <p>${alert.message}</p>
              <div>${new Date(alert.timestamp).toLocaleString()}</div>
            </div>
          `
        })
      }

      // Medium severity alerts
      if (mediumAlerts.length > 0) {
        html += `
          <h3>Medium Severity Issues (${mediumAlerts.length})</h3>
        `

        mediumAlerts.forEach((alert) => {
          html += `
            <div class="alert-item medium">
              <div class="alert-title">
                ${alert.title}
                <span class="alert-severity medium">Medium</span>
              </div>
              <p>${alert.message}</p>
              <div>${new Date(alert.timestamp).toLocaleString()}</div>
            </div>
          `
        })
      }

      // Low severity alerts
      if (lowAlerts.length > 0) {
        html += `
          <h3>Low Severity Issues (${lowAlerts.length})</h3>
        `

        lowAlerts.slice(0, 3).forEach((alert) => {
          html += `
            <div class="alert-item low">
              <div class="alert-title">
                ${alert.title}
                <span class="alert-severity low">Low</span>
              </div>
              <p>${alert.message}</p>
              <div>${new Date(alert.timestamp).toLocaleString()}</div>
            </div>
          `
        })

        if (lowAlerts.length > 3) {
          html += `<p>Plus ${lowAlerts.length - 3} more low severity issues</p>`
        }
      }
    } else {
      html += `<p>No security issues were detected during this period.</p>`
    }

    html += `</div>`
  }

  // Recommendations
  if (options.includeRecommendations) {
    html += `
      <div class="section">
        <h2>Recommendations</h2>
    `

    // Generate recommendations based on data
    const recommendations = generateRecommendations(logs, securityAlerts, {
      errorRate: serverErrors / totalRequests,
      clientErrorRate: clientErrors / totalRequests,
    })

    recommendations.forEach((rec) => {
      html += `
        <div class="recommendation">
          <h3>${rec.title}</h3>
          <p>${rec.description}</p>
        </div>
      `
    })

    html += `</div>`
  }

  // Footer
  html += `
      <div class="footer">
        <p>Report generated by Log Analysis Dashboard</p>
        <p class="no-print">
          <button onclick="window.print()">Print Report</button>
        </p>
      </div>
    </body>
    </html>
  `

  return html
}

/**
 * Analyze security issues specifically for the report
 */
function analyzeSecurityIssuesForReport(logs) {
  // Group logs by IP
  const ipLogs = {}
  logs.forEach((log) => {
    if (!log.ipAddress) return

    if (!ipLogs[log.ipAddress]) {
      ipLogs[log.ipAddress] = []
    }

    ipLogs[log.ipAddress].push(log)
  })

  // Run all security analyses
  const bruteForceAttempts = detectBruteForceAttempts(ipLogs)
  const sqlInjectionAttempts = detectSQLInjection(logs)
  const unusualMethodAttempts = detectUnusualMethods(logs)
  const endpointScanningAttempts = detectEndpointScanning(ipLogs)
  const highErrorRates = detectHighErrorRates(logs)

  // Combine all alerts
  return [
    ...bruteForceAttempts,
    ...sqlInjectionAttempts,
    ...unusualMethodAttempts,
    ...endpointScanningAttempts,
    ...highErrorRates,
  ]
}

/**
 * Generate recommendations based on log analysis
 */
function generateRecommendations(logs, securityAlerts, metrics) {
  const recommendations = []

  // High server error rate
  if (metrics.errorRate > 0.05) {
    recommendations.push({
      title: "Investigate Server Errors",
      description: `Your system is experiencing a high rate of server errors (${(
        metrics.errorRate * 100
      ).toFixed(1)}%). 
                    Review application logs and monitoring systems to identify the root causes of these 5xx errors. 
                    Consider implementing better error tracking and monitoring.`,
    })
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
    })
  }

  // SQL Injection alerts
  const sqlInjectionAlerts = securityAlerts.filter((alert) =>
    alert.title.includes("SQL Injection")
  )

  if (sqlInjectionAlerts.length > 0) {
    recommendations.push({
      title: "Strengthen Input Validation",
      description: `${sqlInjectionAlerts.length} potential SQL injection attempts were detected. 
                    Review your input validation logic and use parameterized queries. Consider 
                    implementing a Web Application Firewall (WAF) to protect against common attack vectors.`,
    })
  }

  // Brute force attempts
  const bruteForceAlerts = securityAlerts.filter((alert) =>
    alert.title.includes("Brute Force")
  )

  if (bruteForceAlerts.length > 0) {
    recommendations.push({
      title: "Implement Rate Limiting",
      description: `Multiple brute force login attempts were detected. Implement rate limiting, 
                    progressive delays, CAPTCHA, and account lockout policies to protect against 
                    automated login attempts.`,
    })
  }

  // Endpoint scanning
  const scanningAlerts = securityAlerts.filter((alert) =>
    alert.title.includes("Endpoint Scanning")
  )

  if (scanningAlerts.length > 0) {
    recommendations.push({
      title: "Enhance API Security",
      description: `${scanningAlerts.length} instances of potential endpoint scanning were detected. 
                    Consider implementing API throttling, requiring authentication for all endpoints, 
                    and adopting the principle of least privilege for API access.`,
    })
  }

  // Add general recommendations if specific ones weren't triggered
  if (recommendations.length < 3) {
    // General performance recommendation
    recommendations.push({
      title: "Optimize Response Times",
      description: `Consider implementing caching strategies and optimizing database queries to improve 
                    overall system performance. Monitor slow endpoints and set up alerting for performance degradation.`,
    })

    // General security recommendation
    if (!recommendations.some((r) => r.title.includes("API Security"))) {
      recommendations.push({
        title: "Regular Security Audits",
        description: `Implement regular security audits and penetration testing to identify vulnerabilities 
                      before they can be exploited. Keep all libraries and dependencies updated to the latest secure versions.`,
      })
    }

    // General monitoring recommendation
    recommendations.push({
      title: "Enhance Monitoring Coverage",
      description: `Expand your monitoring to include more detailed metrics about API performance, 
                    user behavior, and system health. Set up alerts for unusual patterns that may 
                    indicate security issues or performance problems.`,
    })
  }

  return recommendations
}

/**
 * Display the generated report in a new window
 */
function displayReport(reportHtml) {
  const reportWindow = window.open("", "_blank")
  reportWindow.document.write(reportHtml)
  reportWindow.document.close()
}
