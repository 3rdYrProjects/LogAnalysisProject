/**
 * Security analysis and detection
 */

// Update total count

let securityIssueCount = 0
securityIssueCount = securityAlerts.length
/**
 * Analyze logs for security issues and update alerts
 * @param {Array} logs - Filtered logs to analyze
 */
function analyzeSecurityIssues(logs) {
  const securityAlerts = []
  securityIssueCount = 0

  // Group logs by IP to detect suspicious activity
  const ipLogs = groupByIP(logs)

  // Check for brute force login attempts
  const bruteForceAttempts = detectBruteForceAttempts(ipLogs)
  securityAlerts.push(...bruteForceAttempts)

  // Check for SQL injection attempts - direct detection from logs
  const sqlInjectionAttempts = detectSQLInjectionDirect(logs)
  securityAlerts.push(...sqlInjectionAttempts)

  // Pattern-based SQL injection detection
  const patternSQLInjectionAttempts = detectSQLInjection(logs)
  securityAlerts.push(...patternSQLInjectionAttempts)

  // Check for unusual HTTP methods
  const unusualMethodAttempts = detectUnusualMethods(logs)
  securityAlerts.push(...unusualMethodAttempts)

  // Check for unusual endpoint scanning
  const endpointScanningAttempts = detectEndpointScanning(ipLogs)
  securityAlerts.push(...endpointScanningAttempts)

  // Check for large number of errors
  const highErrorRates = detectHighErrorRates(logs)
  securityAlerts.push(...highErrorRates)

  // Check for suspicious user agents
  const suspiciousUserAgents = detectSuspiciousUserAgents(logs)
  securityAlerts.push(...suspiciousUserAgents)

  // Check for suspicious activity patterns
  const suspiciousActivities = detectSuspiciousActivities(logs)
  securityAlerts.push(...suspiciousActivities)
  // Check for honeypot triggers
  const honeypotLogs = detectHoneypotLogs(logs)
  securityAlerts.push(...honeypotLogs)

  // Update total count
  securityIssueCount = securityAlerts.length
  document.getElementById("security-issues").textContent = securityIssueCount

  // Display alerts in the sidebar
  renderSecurityAlerts(securityAlerts)
}

/**
 * Group logs by IP address
 */
function groupByIP(logs) {
  const ipGroups = {}

  logs.forEach((log) => {
    if (!log.ipAddress) return

    if (!ipGroups[log.ipAddress]) {
      ipGroups[log.ipAddress] = []
    }

    ipGroups[log.ipAddress].push(log)
  })

  return ipGroups
}

/**
 * Detect brute force login attempts (multiple failed logins from same IP)
 */

/**
 * Detect honeypot triggered logs
 */
function detectHoneypotLogs(logs) {
  const alerts = []

  logs.forEach((log) => {
    if (
      log.activity &&
      log.activity.toLowerCase().includes("honeypot") &&
      log.details &&
      log.details.toLowerCase().includes("honeypot")
    ) {
      alerts.push({
        title: "Honeypot Triggered - Bot Detected",
        message: log.details,
        severity: "high",
        timestamp: new Date(log.timestamp),
        ip: log.ipAddress,
        path: log.path,
        userId: log.userId || "unknown",
      })
    }
  })

  return alerts
}

function detectBruteForceAttempts(ipLogs) {
  const alerts = []
  const failedLoginThreshold = 3 // Reduced threshold to be more sensitive

  for (const ip in ipLogs) {
    const logs = ipLogs[ip]

    const failedLogins = logs.filter((log) => {
      if (log.activity && log.activity.toLowerCase().includes("login failed")) {
        return true
      }

      if (
        (log.status === 401 || log.status === 403 || log.status === 400) &&
        log.path &&
        log.path.toLowerCase().includes("login")
      ) {
        return true
      }

      if (
        log.details &&
        (log.details.toLowerCase().includes("login failed") ||
          log.details.toLowerCase().includes("failed login") ||
          log.details.toLowerCase().includes("failed attempt") ||
          log.details.toLowerCase().includes("invalid credentials") ||
          log.details.toLowerCase().includes("invalid password"))
      ) {
        return true
      }

      return false
    })

    if (failedLogins.length >= failedLoginThreshold) {
      // Sort by timestamp for latest attempts
      failedLogins.sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      )

      // Calculate time window of attempts
      const latest = new Date(failedLogins[0].timestamp)
      const earliest = new Date(failedLogins[failedLogins.length - 1].timestamp)
      const timeSpan = Math.round((latest - earliest) / 60000) || 1 // minutes (minimum 1)

      // Generate alert
      alerts.push({
        title: "Potential Brute Force Attack",
        message: `${failedLogins.length} failed login attempts from IP ${ip} within ${timeSpan} minutes`,
        severity:
          failedLogins.length >= 8
            ? "high"
            : failedLogins.length >= 5
            ? "medium"
            : "low",
        timestamp: latest,
        ip: ip,
        count: failedLogins.length,
        details:
          "Multiple failed login attempts may indicate password guessing or brute force attacks.",
      })

      console.log(
        `[DETECTION] Brute force detected: ${failedLogins.length} failed logins from ${ip}`,
        failedLogins
      )
    }
  }

  return alerts
}

/**
 * Detect potential SQL injection attempts
 */
function detectSQLInjection(logs) {
  const alerts = []
  const sqlPatterns = [
    "SELECT",
    "UNION",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "1=1",
    "OR 1=1",
    "' OR '",
    "' OR 1=1",
    "--",
    "/*",
    "EXEC",
    "EXECUTE",
    "xp_",
    "sp_",
  ]

  logs.forEach((log) => {
    if (!log.ipAddress) return

    let hasSQLPattern = false
    let matchedPattern = ""
    if (log.path) {
      for (const pattern of sqlPatterns) {
        if (log.path.toUpperCase().includes(pattern)) {
          hasSQLPattern = true
          matchedPattern = pattern
          break
        }
      }
    }
    if (!hasSQLPattern && (log.message || log.details)) {
      const content = (log.message || "") + (log.details || "")
      for (const pattern of sqlPatterns) {
        if (content.toUpperCase().includes(pattern)) {
          hasSQLPattern = true
          matchedPattern = pattern
          break
        }
      }
    }
    if (hasSQLPattern) {
      alerts.push({
        title: "Potential SQL Injection Attempt",
        message: `Suspicious SQL pattern "${matchedPattern}" detected from IP ${log.ipAddress}`,
        severity: "high",
        timestamp: new Date(log.timestamp),
        ip: log.ipAddress,
        path: log.path,
      })
    }
  })

  return alerts
}

function detectUnusualMethods(logs) {
  const alerts = []
  const commonMethods = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
  ]

  logs.forEach((log) => {
    if (!log.method || !log.ipAddress) return

    if (!commonMethods.includes(log.method)) {
      alerts.push({
        title: "Unusual HTTP Method",
        message: `Uncommon HTTP method "${log.method}" used by IP ${log.ipAddress}`,
        severity: "low",
        timestamp: new Date(log.timestamp),
        ip: log.ipAddress,
        method: log.method,
        path: log.path,
      })
    }
  })

  return alerts
}

/**
 * Detect potential endpoint scanning (many different endpoints in short time)
 */
function detectEndpointScanning(ipLogs) {
  const alerts = []
  const endpointThreshold = 15
  const timeWindowMinutes = 5

  for (const ip in ipLogs) {
    const logs = ipLogs[ip]

    if (logs.length < endpointThreshold) continue

    logs.sort(
      (a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    )

    for (let i = 0; i < logs.length - endpointThreshold; i++) {
      const startTime = new Date(logs[i].timestamp)
      const endTime = new Date(logs[i + endpointThreshold - 1].timestamp)

      const minutesDiff = (endTime - startTime) / 60000

      if (minutesDiff <= timeWindowMinutes) {
        const uniquePaths = new Set()
        for (let j = i; j < i + endpointThreshold; j++) {
          if (logs[j].path) uniquePaths.add(logs[j].path)
        }

        if (uniquePaths.size >= endpointThreshold) {
          alerts.push({
            title: "Potential Endpoint Scanning",
            message: `IP ${ip} accessed ${
              uniquePaths.size
            } different endpoints within ${minutesDiff.toFixed(1)} minutes`,
            severity: "medium",
            timestamp: endTime,
            ip: ip,
            count: uniquePaths.size,
          })

          i += endpointThreshold
        }
      }
    }
  }

  return alerts
}

function detectHighErrorRates(logs) {
  const alerts = []

  if (logs.length < 10) return alerts
  const serverErrors = logs.filter((log) => log.status >= 500)
  const errorRate = serverErrors.length / logs.length

  if (errorRate >= 0.1 && serverErrors.length >= 5) {
    const latestError = new Date(
      Math.max(...serverErrors.map((log) => new Date(log.timestamp).getTime()))
    )

    alerts.push({
      title: "High Server Error Rate",
      message: `Server error rate is ${(errorRate * 100).toFixed(1)}% (${
        serverErrors.length
      } out of ${logs.length} requests)`,
      severity: errorRate >= 0.25 ? "high" : "medium",
      timestamp: latestError,
      count: serverErrors.length,
    })
  }

  return alerts
}

function renderSecurityAlerts(alerts) {
  const alertsContainer = document.getElementById("security-alerts")

  if (alerts.length === 0) {
    alertsContainer.innerHTML = `
      <div class="alert-placeholder">No security alerts detected</div>
    `
    return
  }

  const sortedAlerts = alerts.sort((a, b) => {
    const severityOrder = { high: 0, medium: 1, low: 2 }
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity]
    }
    return b.timestamp - a.timestamp
  })

  alertsContainer.innerHTML = sortedAlerts
    .slice(0, 5)
    .map((alert) => {
      const timeString = alert.timestamp.toLocaleString()

      return `
      <div class="alert-item ${alert.severity}">
        <div class="alert-header">
          <div class="alert-title">${alert.title}</div>
          <div class="alert-severity ${alert.severity}">${alert.severity}</div>
        </div>
        <div class="alert-message">${alert.message}</div>
        <div class="alert-meta">
          <span><i class="fas fa-clock"></i> ${timeString}</span>
          ${
            alert.ip
              ? `<span><i class="fas fa-network-wired"></i> ${alert.ip}</span>`
              : ""
          }
        </div>
      </div>
    `
    })
    .join("")

  if (alerts.length > 5) {
    alertsContainer.innerHTML += `
      <div class="alert-view-more">
        <button id="view-all-alerts" class="btn btn-small">
          View all ${alerts.length} alerts
        </button>
      </div>
    `

    setTimeout(() => {
      const viewAllBtn = document.getElementById("view-all-alerts")
      if (viewAllBtn) {
        viewAllBtn.addEventListener("click", () =>
          showAllSecurityAlerts(alerts)
        )
      }
    }, 0)
  }
}

/**
 * Detect SQL injection attempts directly from logs that have activity or details marked as SQL Injection
 */
function detectSQLInjectionDirect(logs) {
  const alerts = []

  logs.forEach((log) => {
    // Check for explicit SQL injection markers
    if (
      log.activity === "SQL Injection Attempt" ||
      (log.details && log.details.toLowerCase().includes("sql injection"))
    ) {
      alerts.push({
        title: "SQL Injection Attempt",
        message: log.details || `Suspicious activity from IP ${log.ipAddress}`,
        severity: "high",
        timestamp: new Date(log.timestamp),
        ip: log.ipAddress,
        path: log.path,
        userId: log.userId || "unknown",
      })
    }
  })

  return alerts
}

/**
 * Detect suspicious user agents that might indicate automated tools or scanners
 */
function detectSuspiciousUserAgents(logs) {
  const alerts = []
  const suspiciousAgents = [
    "sqlmap",
    "nikto",
    "nmap",
    "nuclei",
    "dirbuster",
    "gobuster",
    "wpscan",
    "hydra",
    "medusa",
    "burpsuite",
    "zap",
    "python-requests",
  ]

  // Group logs by IP and user agent
  const ipUserAgentMap = {}

  logs.forEach((log) => {
    if (!log.ipAddress || !log.userAgent) return

    const key = `${log.ipAddress}_${log.userAgent}`
    if (!ipUserAgentMap[key]) {
      ipUserAgentMap[key] = {
        ip: log.ipAddress,
        userAgent: log.userAgent,
        logs: [],
      }
    }

    ipUserAgentMap[key].logs.push(log)
  })

  for (const key in ipUserAgentMap) {
    const item = ipUserAgentMap[key]

    for (const agent of suspiciousAgents) {
      if (item.userAgent.toLowerCase().includes(agent)) {
        // Get the most recent log with this user agent
        const recentLog = item.logs.sort(
          (a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        )[0]

        alerts.push({
          title: "Suspicious User Agent",
          message: `IP ${item.ip} is using suspicious user agent: "${item.userAgent}"`,
          severity: "medium",
          timestamp: new Date(recentLog.timestamp),
          ip: item.ip,
          path: recentLog.path,
          count: item.logs.length,
        })

        break // Only add one alert per IP/user-agent pair
      }
    }
  }

  return alerts
}

/**
 * Detect suspicious activities based on the activity field
 */
function detectSuspiciousActivities(logs) {
  const alerts = []
  const suspiciousActivities = [
    "Endpoint Scan",
    "File Inclusion",
    "Command Injection",
    "XSS Attempt",
    "CSRF Attempt",
  ]

  logs.forEach((log) => {
    if (!log.activity) return

    // Check for directly suspicious activities
    for (const activity of suspiciousActivities) {
      if (log.activity.includes(activity)) {
        alerts.push({
          title: log.activity,
          message:
            log.details || `Suspicious activity from IP ${log.ipAddress}`,
          severity: "high",
          timestamp: new Date(log.timestamp),
          ip: log.ipAddress,
          path: log.path,
        })
        return // Only add one alert per log
      }
    }

    // Special check for Login Failed with unusual details
    if (log.activity === "Login Failed" && log.details) {
      if (
        log.details.includes("'") ||
        log.details.includes("--") ||
        log.details.includes(";") ||
        log.details.includes("=")
      ) {
        alerts.push({
          title: "Potential Attack in Login",
          message: `Suspicious characters in login attempt: "${log.details}"`,
          severity: "medium",
          timestamp: new Date(log.timestamp),
          ip: log.ipAddress,
          path: log.path,
        })
      }
    }
  })

  return alerts
}

/**
 * Show all security alerts in a modal
 */
function showAllSecurityAlerts(alerts) {
  const modal = document.getElementById("log-detail-modal")
  const content = document.getElementById("log-detail-content")

  // Sort alerts by severity and timestamp
  const sortedAlerts = alerts.sort((a, b) => {
    const severityOrder = { high: 0, medium: 1, low: 2 }
    if (severityOrder[a.severity] !== severityOrder[b.severity]) {
      return severityOrder[a.severity] - severityOrder[b.severity]
    }
    return b.timestamp - a.timestamp
  })

  // Generate HTML for alerts
  let html = `
    <div class="security-alerts-modal">
      <h3>All Security Alerts (${alerts.length})</h3>
      <div class="security-alerts-list">
  `

  html += sortedAlerts
    .map((alert) => {
      const timeString = alert.timestamp.toLocaleString()

      return `
      <div class="alert-item ${alert.severity}">
        <div class="alert-header">
          <div class="alert-title">${alert.title}</div>
          <div class="alert-severity ${alert.severity}">${alert.severity}</div>
        </div>
        <div class="alert-message">${alert.message}</div>
        <div class="alert-meta">
          <span><i class="fas fa-clock"></i> ${timeString}</span>
          ${
            alert.ip
              ? `<span><i class="fas fa-network-wired"></i> ${alert.ip}</span>`
              : ""
          }
          ${
            alert.path
              ? `<span><i class="fas fa-link"></i> ${alert.path}</span>`
              : ""
          }
        </div>
      </div>
    `
    })
    .join("")

  html += `
      </div>
    </div>
  `

  content.innerHTML = html
  modal.style.display = "block"
}
