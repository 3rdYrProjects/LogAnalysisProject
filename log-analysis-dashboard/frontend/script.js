const API_BASE = "http://localhost:4000"
let allLogs = []
let currentPage = 1
let pageSize = 20
let sortField = "timestamp"
let sortDirection = "desc"
let liveMode = false
let liveInterval = null

/**
 * Fetch logs from the API
 * @param {boolean} silent - If true, don't show loading states
 */
async function fetchLogs(silent = false) {
  try {
    if (!silent) {
      document.getElementById("logs-table").innerHTML =
        '<tr><td colspan="9" class="loading-cell">Loading logs...</td></tr>'
    }

    const res = await fetch(`${API_BASE}/logs`)
    if (!res.ok) {
      throw new Error(`HTTP error: ${res.status}`)
    }

    allLogs = await res.json()

    // Calculate metrics
    calculateMetrics(allLogs)

    // Apply filters and render
    applyAllFiltersAndRender()

    return allLogs
  } catch (error) {
    console.error("Error fetching logs:", error)
    document.getElementById(
      "logs-table"
    ).innerHTML = `<tr><td colspan="9" class="error-cell">
        Error loading logs: ${error.message}. Please check your connection and try again.
      </td></tr>`
    return []
  }
}

/**
 * Calculate dashboard metrics from logs
 */
function calculateMetrics(logs) {
  // Total requests
  document.getElementById("total-requests").textContent = logs.length

  // Error count (status >= 400)
  const errorCount = logs.filter((log) => log.status >= 400).length
  document.getElementById("error-count").textContent = errorCount

  // Average response time (if available in the logs)
  const logsWithTime = logs.filter((log) => log.responseTime)
  if (logsWithTime.length > 0) {
    const avgTime = Math.round(
      logsWithTime.reduce((sum, log) => sum + (log.responseTime || 0), 0) /
        logsWithTime.length
    )
    document.getElementById("response-time").textContent = `${avgTime} ms`
  } else {
    document.getElementById("response-time").textContent = "N/A"
  }

  // Security issues count will be updated by security.js
}

/**
 * Apply all filters to logs and render results
 */
function applyAllFiltersAndRender() {
  const level = document.getElementById("filter-level").value
  const method = document.getElementById("filter-method").value
  const status = document.getElementById("filter-status").value.trim()
  const path = document.getElementById("filter-path").value.trim()
  const userId = document.getElementById("filter-userid").value.trim()
  const ip = document.getElementById("filter-ip").value.trim()
  const search = document.getElementById("search-box").value.toLowerCase()
  const rangeValue = document.getElementById("date-range").value

  let startDate = null
  let endDate = new Date()

  if (rangeValue === "custom") {
    const fromDate = document.getElementById("date-from").value
    const toDate = document.getElementById("date-to").value

    if (fromDate) startDate = new Date(fromDate)
    if (toDate) endDate = new Date(toDate)
  } else if (rangeValue !== "all") {
    const days = parseInt(rangeValue)
    startDate = new Date()
    startDate.setDate(startDate.getDate() - days)
  }

  const filtered = allLogs.filter((log) => {
    const logTime = new Date(log.timestamp)

    return (
      (!level || log.level === level) &&
      (!method || log.method === method) &&
      (!status || (log.status && log.status.toString().includes(status))) &&
      (!path ||
        (log.path && log.path.toLowerCase().includes(path.toLowerCase()))) &&
      (!userId ||
        (log.userId &&
          log.userId.toLowerCase().includes(userId.toLowerCase()))) &&
      (!ip || (log.ipAddress && log.ipAddress.includes(ip))) &&
      (!search ||
        (log.message && log.message.toLowerCase().includes(search)) ||
        (log.userId && log.userId.toLowerCase().includes(search)) ||
        (log.details && log.details.toLowerCase().includes(search))) &&
      (startDate ? logTime >= startDate : true) &&
      (endDate ? logTime <= endDate : true)
    )
  })

  // Sort the filtered logs
  sortLogs(filtered)

  // Render the table and update pagination
  renderTable(filtered)

  // Update the charts
  updateAllCharts(filtered)

  // Check for security issues
  analyzeSecurityIssues(filtered)
}

/**
 * Sort logs by the specified field and direction
 */
function sortLogs(logs) {
  logs.sort((a, b) => {
    let valueA, valueB

    // Handle special fields
    if (sortField === "time" || sortField === "timestamp") {
      valueA = new Date(a.timestamp).getTime()
      valueB = new Date(b.timestamp).getTime()
    } else if (sortField === "id") {
      valueA = a._id
      valueB = b._id
    } else if (sortField === "ip") {
      valueA = a.ipAddress || ""
      valueB = b.ipAddress || ""
    } else {
      valueA = a[sortField] || ""
      valueB = b[sortField] || ""
    }

    // Compare values based on type
    if (typeof valueA === "string") {
      const comparison = valueA.localeCompare(valueB)
      return sortDirection === "asc" ? comparison : -comparison
    } else {
      return sortDirection === "asc" ? valueA - valueB : valueB - valueA
    }
  })
}

/**
 * Get color for log level
 */
function getLevelColor(level) {
  switch (level) {
    case "error":
      return "var(--red)"
    case "warn":
      return "var(--orange)"
    case "info":
      return "var(--blue)"
    case "debug":
      return "var(--muted)"
    default:
      return "var(--muted)"
  }
}

/**
 * Get color for HTTP status
 */
function getStatusColor(status) {
  const code = parseInt(status)
  if (code >= 200 && code < 300) return "var(--green)"
  if (code >= 300 && code < 400) return "var(--blue)"
  if (code >= 400 && code < 500) return "var(--orange)"
  if (code >= 500) return "var(--red)"
  return "var(--muted)"
}

/**
 * Render logs table with pagination
 */
function renderTable(logs) {
  const tableBody = document.getElementById("logs-table")
  tableBody.innerHTML = ""

  // Update log count and pagination info
  document.getElementById("log-count").textContent = `${logs.length} logs found`

  // Calculate pagination
  const totalPages = Math.ceil(logs.length / pageSize)
  if (currentPage > totalPages) {
    currentPage = totalPages > 0 ? totalPages : 1
  }

  const startIndex = (currentPage - 1) * pageSize
  const endIndex = Math.min(startIndex + pageSize, logs.length)
  const pageInfo = `Page ${currentPage} of ${totalPages || 1}`
  document.getElementById("page-info").textContent = pageInfo

  // Enable/disable pagination buttons
  document.getElementById("prev-page").disabled = currentPage <= 1
  document.getElementById("next-page").disabled = currentPage >= totalPages

  // No logs found?
  if (logs.length === 0) {
    tableBody.innerHTML =
      '<tr><td colspan="9" class="empty-cell">No logs match the current filters</td></tr>'
    return
  }

  // Slice the logs for the current page
  const currentPageLogs = logs.slice(startIndex, endIndex)

  // Render the logs
  currentPageLogs.forEach((log) => {
    const row = document.createElement("tr")

    // Format timestamp
    const timestamp = new Date(log.timestamp)
    const formattedDate = timestamp.toLocaleString()

    // Truncate message for table display
    const truncatedMessage =
      (log.message || log.details || "").substring(0, 80) +
      ((log.message || log.details || "").length > 80 ? "..." : "")

    row.innerHTML = `
      <td>${log._id || ""}</td>
      <td>${log.ipAddress || ""}</td>
      <td>${formattedDate}</td>
      <td><span class="badge" style="background-color: ${getLevelColor(
        log.level
      )}">${log.level || ""}</span></td>
      <td>${log.method || ""}</td>
      <td>${log.path || ""}</td>
      <td><span class="badge" style="background-color: ${getStatusColor(
        log.status
      )}">${log.status || ""}</span></td>
      <td>${truncatedMessage}</td>
      <td class="action-cell">
        <button class="view-log-btn" data-id="${
          log._id
        }"><i class="fas fa-eye"></i></button>
      </td>
    `

    tableBody.appendChild(row)
  })

  // Add event listeners to log detail buttons
  document.querySelectorAll(".view-log-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const logId = btn.getAttribute("data-id")
      showLogDetails(logId)
    })
  })
}

/**
 * Show detailed log information in a modal
 */
function showLogDetails(logId) {
  const log = allLogs.find((l) => l._id === logId)
  if (!log) return

  const modal = document.getElementById("log-detail-modal")
  const content = document.getElementById("log-detail-content")

  // Format timestamp
  const timestamp = new Date(log.timestamp)
  const formattedDate = timestamp.toLocaleString()

  // Build detailed content
  let html = `
    <div class="log-detail-group">
      <h3><i class="fas fa-info-circle"></i> Basic Information</h3>
      <div class="log-detail-row">
        <div class="log-detail-label">Log ID</div>
        <div class="log-detail-value">${log._id || "N/A"}</div>
      </div>
      <div class="log-detail-row">
        <div class="log-detail-label">Timestamp</div>
        <div class="log-detail-value">${formattedDate}</div>
      </div>
      <div class="log-detail-row">
        <div class="log-detail-label">Level</div>
        <div class="log-detail-value">
          <span class="log-badge" style="background-color: ${getLevelColor(
            log.level
          )}">${log.level || "N/A"}</span>
        </div>
      </div>
      <div class="log-detail-row">
        <div class="log-detail-label">IP Address</div>
        <div class="log-detail-value">${log.ipAddress || "N/A"}</div>
      </div>
    </div>
    
    <div class="log-detail-group">
      <h3><i class="fas fa-exchange-alt"></i> Request Details</h3>
      <div class="log-detail-row">
        <div class="log-detail-label">HTTP Method</div>
        <div class="log-detail-value">${log.method || "N/A"}</div>
      </div>
      <div class="log-detail-row">
        <div class="log-detail-label">Request Path</div>
        <div class="log-detail-value">${log.path || "N/A"}</div>
      </div>
      <div class="log-detail-row">
        <div class="log-detail-label">Status Code</div>
        <div class="log-detail-value">
          <span class="log-badge" style="background-color: ${getStatusColor(
            log.status
          )}">${log.status || "N/A"}</span>
        </div>
      </div>
    </div>
  `

  // Add message and details if available
  if (log.message || log.details) {
    html += `
      <div class="log-detail-group">
        <h3><i class="fas fa-comment-alt"></i> Message & Details</h3>
        <div class="log-detail-row">
          <div class="log-detail-label">Message</div>
          <div class="log-detail-value">${log.message || "N/A"}</div>
        </div>
    `

    if (log.details) {
      html += `
        <div class="log-detail-row">
          <div class="log-detail-label">Additional Details</div>
          <div class="log-detail-value">
            <pre class="code-block">${formatJson(log.details)}</pre>
          </div>
        </div>
      `
    }

    html += `</div>`
  }

  // Add user data if available
  if (log.userId || log.user) {
    html += `
      <div class="log-detail-group">
        <h3><i class="fas fa-user"></i> User Information</h3>
        <div class="log-detail-row">
          <div class="log-detail-label">User ID</div>
          <div class="log-detail-value">${log.userId || "N/A"}</div>
        </div>
    `

    if (log.user) {
      html += `
        <div class="log-detail-row">
          <div class="log-detail-label">User Details</div>
          <div class="log-detail-value">
            <pre class="code-block">${formatJson(log.user)}</pre>
          </div>
        </div>
      `
    }

    html += `</div>`
  }

  // Add stack trace for errors
  if (log.level === "error" && log.stack) {
    html += `
      <div class="log-detail-group">
        <h3><i class="fas fa-exclamation-triangle"></i> Stack Trace</h3>
        <pre class="code-block">${log.stack}</pre>
      </div>
    `
  }

  // Add request headers or body if available
  if (log.headers || log.body) {
    html += `<div class="log-detail-group">
      <h3><i class="fas fa-code"></i> Request Data</h3>`

    if (log.headers) {
      html += `
        <div class="log-detail-row">
          <div class="log-detail-label">Headers</div>
          <div class="log-detail-value">
            <pre class="code-block">${formatJson(log.headers)}</pre>
          </div>
        </div>
      `
    }

    if (log.body) {
      html += `
        <div class="log-detail-row">
          <div class="log-detail-label">Request Body</div>
          <div class="log-detail-value">
            <pre class="code-block">${formatJson(log.body)}</pre>
          </div>
        </div>
      `
    }

    html += `</div>`
  }

  content.innerHTML = html
  modal.style.display = "block"
}

/**
 * Format JSON data for display
 */
function formatJson(data) {
  if (!data) return ""

  try {
    if (typeof data === "string") {
      try {
        // Try to parse as JSON
        const parsed = JSON.parse(data)
        return JSON.stringify(parsed, null, 2)
      } catch {
        // Not JSON, return as is
        return data
      }
    } else {
      return JSON.stringify(data, null, 2)
    }
  } catch (e) {
    return String(data)
  }
}

/**
 * Toggle live mode for real-time log fetching
 */
function toggleLiveMode() {
  liveMode = !liveMode
  const liveBtn = document.getElementById("live-toggle")

  if (liveMode) {
    liveBtn.innerHTML = '<i class="fas fa-bolt"></i> Live Mode: On'
    liveBtn.classList.add("btn-active")

    // Start periodic fetching
    liveInterval = setInterval(() => {
      fetchLogs(true)
    }, 5000) // Fetch every 5 seconds
  } else {
    liveBtn.innerHTML = '<i class="fas fa-bolt"></i> Live Mode: Off'
    liveBtn.classList.remove("btn-active")

    // Stop periodic fetching
    if (liveInterval) {
      clearInterval(liveInterval)
      liveInterval = null
    }
  }
}

/**
 * Toggle theme between light and dark
 */
function toggleTheme() {
  const body = document.body
  const isDarkMode = body.classList.contains("dark-mode")

  if (isDarkMode) {
    body.classList.remove("dark-mode")
    localStorage.setItem("theme", "light")
  } else {
    body.classList.add("dark-mode")
    localStorage.setItem("theme", "dark")
  }

  // Update all charts to reflect theme change
  updateAllCharts(allLogs.filter((l) => true)) // Re-filter to get current filtered logs
}

/**
 * Clear all filters
 */
function clearFilters() {
  document.getElementById("filter-level").value = ""
  document.getElementById("filter-method").value = ""
  document.getElementById("filter-status").value = ""
  document.getElementById("filter-path").value = ""
  document.getElementById("filter-userid").value = ""
  document.getElementById("filter-ip").value = ""
  document.getElementById("search-box").value = ""
  document.getElementById("date-range").value = "3" // Default to last 3 days

  // Hide custom date range if visible
  document.getElementById("custom-date-range").classList.add("hidden")

  // Apply filters immediately
  applyAllFiltersAndRender()
}

// ==================== Event Listeners ====================

document.addEventListener("DOMContentLoaded", () => {
  // Initial data fetch
  fetchLogs()

  // Setup filter change handlers
  ;[
    "filter-level",
    "filter-method",
    "filter-status",
    "filter-path",
    "filter-userid",
    "filter-ip",
    "search-box",
    "date-range",
    "date-from",
    "date-to",
  ].forEach((id) => {
    document
      .getElementById(id)
      .addEventListener("input", applyAllFiltersAndRender)
  })

  // Date range handler for showing/hiding custom date inputs
  document.getElementById("date-range").addEventListener("change", (e) => {
    const customDateContainer = document.getElementById("custom-date-range")
    if (e.target.value === "custom") {
      customDateContainer.classList.remove("hidden")
    } else {
      customDateContainer.classList.add("hidden")
    }
    applyAllFiltersAndRender()
  })

  // Refresh button
  document
    .getElementById("refresh-btn")
    .addEventListener("click", () => fetchLogs())

  // Live toggle button
  document
    .getElementById("live-toggle")
    .addEventListener("click", toggleLiveMode)

  // Theme toggle
  document
    .getElementById("theme-toggle")
    .addEventListener("change", toggleTheme)

  // Clear filters button
  document
    .getElementById("clear-filters")
    .addEventListener("click", clearFilters)

  // Pagination handlers
  document.getElementById("prev-page").addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--
      applyAllFiltersAndRender()
    }
  })

  document.getElementById("next-page").addEventListener("click", () => {
    currentPage++
    applyAllFiltersAndRender()
  })

  // Page size change handler
  document.getElementById("page-size").addEventListener("change", (e) => {
    pageSize = parseInt(e.target.value)
    currentPage = 1 // Reset to first page
    applyAllFiltersAndRender()
  })

  // Table sorting
  document.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.getAttribute("data-sort")

      // If clicking the same field, toggle direction
      if (field === sortField) {
        sortDirection = sortDirection === "asc" ? "desc" : "asc"
      } else {
        sortField = field
        sortDirection = "desc" // Default to descending for new sort field
      }

      // Update UI to show sort indicators
      document.querySelectorAll("th.sortable").forEach((header) => {
        header.classList.remove("sorted-asc", "sorted-desc")
      })

      th.classList.add(sortDirection === "asc" ? "sorted-asc" : "sorted-desc")

      // Reapply filters and sorting
      applyAllFiltersAndRender()
    })
  })

  // Modal close handlers
  document.querySelectorAll(".close-modal").forEach((closeBtn) => {
    closeBtn.addEventListener("click", () => {
      document.querySelectorAll(".modal").forEach((modal) => {
        modal.style.display = "none"
      })
    })
  })

  // Close modals when clicking outside
  window.addEventListener("click", (e) => {
    document.querySelectorAll(".modal").forEach((modal) => {
      if (e.target === modal) {
        modal.style.display = "none"
      }
    })
  })

  // Load theme preference
  const savedTheme = localStorage.getItem("theme")
  if (savedTheme === "dark") {
    document.body.classList.add("dark-mode")
    document.getElementById("theme-toggle").checked = true
  }

  // Setup report generation handlers
  setupReportHandlers()
})
