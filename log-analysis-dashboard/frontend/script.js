const API_BASE = "http://localhost:4000"
let allLogs = []

async function fetchLogs() {
  const res = await fetch(`${API_BASE}/logs`)
  allLogs = await res.json()
  applyAllFiltersAndRender()
}

function applyAllFiltersAndRender() {
  const level = document.getElementById("filter-level").value
  const method = document.getElementById("filter-method").value
  const status = document.getElementById("filter-status").value.trim()
  const path = document.getElementById("filter-path").value.trim()
  const search = document.getElementById("search-box").value.toLowerCase()
  const rangeValue = document.getElementById("date-range").value
  let startDate = null

  if (rangeValue !== "all") {
    const days = parseInt(rangeValue)
    startDate = new Date()
    startDate.setDate(startDate.getDate() - days)
  }

  const filtered = allLogs.filter((log) => {
    const logTime = new Date(log.timestamp)
    return (
      (!level || log.level === level) &&
      (!method || log.method === method) &&
      (!status || log.status.toString().includes(status)) &&
      (!path || (log.path && log.path.includes(path))) &&
      (!search ||
        (log.message && log.message.toLowerCase().includes(search)) ||
        (log.userId && log.userId.toLowerCase().includes(search))) &&
      (startDate ? logTime >= startDate : true)
    )
  })

  renderTable(filtered)
  renderChart(filtered)
}

function getLevelColor(level) {
  switch (level) {
    case "error":
      return "var(--red)"
    case "warn":
      return "var(--orange)"
    case "info":
      return "var(--blue)"
    case "debug":
      return "var(--gray)"
    default:
      return "var(--gray)"
  }
}

function getStatusColor(status) {
  const code = parseInt(status)
  if (code >= 200 && code < 300) return "var(--green)"
  if (code >= 300 && code < 400) return "var(--blue)"
  if (code >= 400 && code < 500) return "var(--red)"
  if (code >= 500) return "var(--red)"
  return "var(--gray)"
}

function renderTable(logs) {
  const tableBody = document.getElementById("logs-table")
  tableBody.innerHTML = ""
  logs.forEach((log) => {
    const row = document.createElement("tr")
    row.innerHTML = `
      <td>${log._id}</td>
      <td>${log.ipAddress}</td>
      <td>${new Date(log.timestamp).toLocaleString()}</td>
      <td><span class="badge" style="background-color: ${getLevelColor(
        log.level
      )}">${log.level}</span></td>
      <td>${log.method}</td>
      <td>${log.path}</td>
      <td><span class="badge" style="background-color: ${getStatusColor(
        log.status
      )}">${log.status}</span></td>
      <td>${log.message || log.details || ""}</td>
    `
    tableBody.appendChild(row)
  })
}

let chartInstance
function renderChart(logs) {
  const methodCounts = logs.reduce((acc, log) => {
    acc[log.method] = (acc[log.method] || 0) + 1
    return acc
  }, {})

  const labels = Object.keys(methodCounts)
  const data = Object.values(methodCounts)

  const ctx = document.getElementById("activity-chart").getContext("2d")
  if (chartInstance) chartInstance.destroy()

  chartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "HTTP Method Count",
          data,
          backgroundColor: "#2563eb",
          borderRadius: 6,
        },
      ],
    },
    options: {
      plugins: {
        legend: {
          display: false,
        },
      },
      responsive: true,
      scales: {
        y: {
          beginAtZero: true,
          ticks: { stepSize: 1 },
        },
      },
    },
  })
}

document.addEventListener("DOMContentLoaded", () => {
  fetchLogs()
  ;[
    "filter-level",
    "filter-method",
    "filter-status",
    "filter-path",
    "search-box",
    "date-range",
  ].forEach((id) => {
    document
      .getElementById(id)
      .addEventListener("input", applyAllFiltersAndRender)
  })

  document.getElementById("refresh-btn").addEventListener("click", fetchLogs)
})
