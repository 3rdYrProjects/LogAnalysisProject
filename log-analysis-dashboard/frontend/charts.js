// Chart.js configuration and helpers
let timeChart, levelsChart, methodsChart, statusChart

/**
 * Initialize all charts with empty data
 */
function initCharts() {
  const isDarkMode = document.body.classList.contains("dark-mode")
  Chart.defaults.color = isDarkMode ? "#d1d5db" : "#64748b"
  Chart.defaults.borderColor = isDarkMode ? "#374151" : "#e2e8f0"

  // Activity over time chart (line chart)
  const timeCtx = document.getElementById("activity-chart").getContext("2d")
  timeChart = new Chart(timeCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Requests",
          data: [],
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.1)",
          borderWidth: 2,
          tension: 0.2,
          fill: true,
          pointBackgroundColor: "#3b82f6",
          pointRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        },
        tooltip: {
          mode: "index",
          intersect: false,
        },
      },
      scales: {
        x: {
          grid: {
            display: false,
          },
        },
        y: {
          beginAtZero: true,
          ticks: {
            precision: 0,
          },
        },
      },
    },
  })

  // Log levels distribution (doughnut chart)
  const levelsCtx = document.getElementById("levels-chart").getContext("2d")
  levelsChart = new Chart(levelsCtx, {
    type: "doughnut",
    data: {
      labels: ["info", "warn", "error", "debug"],
      datasets: [
        {
          data: [0, 0, 0, 0],
          backgroundColor: [
            "var(--blue)",
            "var(--orange)",
            "var(--red)",
            "var(--gray)",
          ],
          borderWidth: 1,
          borderColor: isDarkMode ? "#1f2937" : "#ffffff",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: {
            padding: 20,
            usePointStyle: true,
            pointStyle: "circle",
          },
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const label = context.label || ""
              const value = context.formattedValue
              const total = context.dataset.data.reduce((a, b) => a + b, 0)
              const percentage =
                total > 0 ? Math.round((context.raw / total) * 100) : 0
              return `${label}: ${value} (${percentage}%)`
            },
          },
        },
      },
      cutout: "70%",
    },
  })

  // HTTP Methods chart (bar chart)
  const methodsCtx = document.getElementById("methods-chart").getContext("2d")
  methodsChart = new Chart(methodsCtx, {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        {
          label: "HTTP Methods",
          data: [],
          backgroundColor: [
            "var(--blue)",
            "var(--green)",
            "var(--orange)",
            "var(--red)",
            "var(--purple)",
          ],
          borderRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      plugins: {
        legend: {
          display: false,
        },
        title: {
          display: true,
          text: "HTTP Methods",
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: {
            precision: 0,
          },
        },
      },
    },
  })

  // Status codes chart (horizontal bar chart)
  const statusCtx = document.getElementById("status-chart").getContext("2d")
  statusChart = new Chart(statusCtx, {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        {
          label: "Status Codes",
          data: [],
          backgroundColor: function (context) {
            const status = context.chart.data.labels[context.dataIndex]
            const code = parseInt(status)
            if (code >= 200 && code < 300) return "var(--green)"
            if (code >= 300 && code < 400) return "var(--blue)"
            if (code >= 400 && code < 500) return "var(--orange)"
            return "var(--red)"
          },
          borderRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      plugins: {
        legend: {
          display: false,
        },
        title: {
          display: true,
          text: "Status Codes",
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: {
            precision: 0,
          },
        },
      },
    },
  })
}

/**
 * Update all charts with new data
 * @param {Array} logs - Filtered logs to display in charts
 */
function updateAllCharts(logs) {
  updateTimeChart(logs)
  updateLevelsChart(logs)
  updateMethodsChart(logs)
  updateStatusChart(logs)
}

/**
 * Update the activity over time chart
 */
function updateTimeChart(logs) {
  const timeChartType = document.getElementById("time-chart-type").value

  // Group logs by time period based on selected type
  const groupedData = {}

  logs.forEach((log) => {
    const date = new Date(log.timestamp)
    let timeKey

    if (timeChartType === "hour") {
      // Group by hour
      timeKey = new Date(
        date.getFullYear(),
        date.getMonth(),
        date.getDate(),
        date.getHours()
      ).toISOString()
    } else if (timeChartType === "day") {
      // Group by day
      timeKey = new Date(
        date.getFullYear(),
        date.getMonth(),
        date.getDate()
      ).toISOString()
    } else {
      // Group by week (starting Monday)
      const d = new Date(date)
      const day = d.getDay()
      const diff = d.getDate() - day + (day === 0 ? -6 : 1) // Adjust for Sunday
      timeKey = new Date(d.setDate(diff)).toISOString()
    }

    groupedData[timeKey] = (groupedData[timeKey] || 0) + 1
  })

  // Sort timestamps and prepare data for chart
  const timestamps = Object.keys(groupedData).sort()
  const counts = timestamps.map((t) => groupedData[t])

  // Format labels based on grouping type
  const labels = timestamps.map((timestamp) => {
    const date = new Date(timestamp)
    if (timeChartType === "hour") {
      return date.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
      })
    } else if (timeChartType === "day") {
      return date.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
      })
    } else {
      return `Week of ${date.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
      })}`
    }
  })

  // Update chart data
  timeChart.data.labels = labels
  timeChart.data.datasets[0].data = counts
  timeChart.update()
}

/**
 * Update the log levels distribution chart
 */
function updateLevelsChart(logs) {
  // Count logs by level
  const levelCounts = {
    info: 0,
    warn: 0,
    error: 0,
    debug: 0,
  }

  logs.forEach((log) => {
    if (log.level && levelCounts.hasOwnProperty(log.level)) {
      levelCounts[log.level]++
    }
  })

  // Update chart data
  levelsChart.data.datasets[0].data = [
    levelCounts.info,
    levelCounts.warn,
    levelCounts.error,
    levelCounts.debug,
  ]

  levelsChart.update()
}

/**
 * Update the HTTP methods chart
 */
function updateMethodsChart(logs) {
  // Count logs by HTTP method
  const methodCounts = {}

  logs.forEach((log) => {
    if (log.method) {
      methodCounts[log.method] = (methodCounts[log.method] || 0) + 1
    }
  })

  // Sort methods by count (descending)
  const sortedMethods = Object.keys(methodCounts).sort(
    (a, b) => methodCounts[b] - methodCounts[a]
  )

  // Update chart data
  methodsChart.data.labels = sortedMethods
  methodsChart.data.datasets[0].data = sortedMethods.map(
    (method) => methodCounts[method]
  )

  methodsChart.update()
}

/**
 * Update the status codes chart
 */
function updateStatusChart(logs) {
  // Count logs by status code
  const statusCounts = {}

  logs.forEach((log) => {
    if (log.status) {
      statusCounts[log.status] = (statusCounts[log.status] || 0) + 1
    }
  })

  // Sort status codes by count (descending)
  const sortedStatuses = Object.keys(statusCounts).sort(
    (a, b) => statusCounts[b] - statusCounts[a]
  )

  // Update chart data
  statusChart.data.labels = sortedStatuses
  statusChart.data.datasets[0].data = sortedStatuses.map(
    (status) => statusCounts[status]
  )

  statusChart.update()
}

// Initialize charts when the DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  initCharts()

  // Add event listener for time chart type changes
  document.getElementById("time-chart-type").addEventListener("change", () => {
    // Get currently filtered logs
    const filtered = allLogs.filter(() => true) // This will apply current filters
    updateTimeChart(filtered)
  })
})

/**
 * Update chart theme when the theme changes
 */
function updateChartsTheme() {
  const isDarkMode = document.body.classList.contains("dark-mode")
  Chart.defaults.color = isDarkMode ? "#d1d5db" : "#64748b"
  Chart.defaults.borderColor = isDarkMode ? "#374151" : "#e2e8f0"

  // Update doughnut chart border color
  if (levelsChart && levelsChart.data.datasets[0]) {
    levelsChart.data.datasets[0].borderColor = isDarkMode
      ? "#1f2937"
      : "#ffffff"
  }

  // Update all charts
  ;[timeChart, levelsChart, methodsChart, statusChart].forEach((chart) => {
    if (chart) chart.update()
  })
}
