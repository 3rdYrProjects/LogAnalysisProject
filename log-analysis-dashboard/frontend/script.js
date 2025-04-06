// === UPDATED script.js ===
const API_BASE = "http://localhost:4000"

let allLogs = []

async function fetchSummaryAndRender() {
  try {
    const summaryResponse = await fetch(`${API_BASE}/logs/summary`)
    const summaryData = await summaryResponse.json()

    document.getElementById(
      "total-logs"
    ).textContent = `Total Logs: ${summaryData.totalLogs}`

    const activityChart = document
      .getElementById("activity-chart")
      .getContext("2d")
    new Chart(activityChart, {
      type: "bar",
      data: {
        labels: summaryData.activities.map((a) => a._id),
        datasets: [
          {
            label: "Activities",
            data: summaryData.activities.map((a) => a.count),
            backgroundColor: "rgba(54, 162, 235, 0.6)",
          },
        ],
      },
    })

    const statusChart = document.getElementById("status-chart").getContext("2d")
    new Chart(statusChart, {
      type: "doughnut",
      data: {
        labels: summaryData.statuses.map((s) => s._id),
        datasets: [
          {
            label: "Statuses",
            data: summaryData.statuses.map((s) => s.count),
            backgroundColor: ["#36A2EB", "#FF6384", "#FFCE56"],
          },
        ],
      },
    })
  } catch (err) {
    console.error("Summary error:", err)
  }
}

async function fetchAndRenderLogs() {
  try {
    const logsResponse = await fetch(`${API_BASE}/logs`)
    allLogs = await logsResponse.json()
    renderLogsTable(allLogs)
  } catch (err) {
    console.error("Logs error:", err)
  }
}

function renderLogsTable(logs) {
  const logsTable = document.getElementById("logs-table")
  logsTable.innerHTML = ""
  logs.forEach((log) => {
    const row = document.createElement("tr")
    row.innerHTML = `
      <td>${log._id}</td>
      <td>${new Date(log.timestamp).toLocaleString()}</td>
      <td>${log.level || "info"}</td>
      <td>${log.service || "web"}</td>
      <td>${log.method || "GET"}</td>
      <td>${log.path || "/"}</td>
      <td>${log.status || 200}</td>
      <td>${log.message || log.details}</td>
    `
    logsTable.appendChild(row)
  })
}

function applyFilters() {
  const userInput = document.getElementById("filter-user").value.toLowerCase()
  const statusInput = document
    .getElementById("filter-status")
    .value.toLowerCase()

  const filtered = allLogs.filter((log) => {
    return (
      (!userInput ||
        (log.userId && log.userId.toLowerCase().includes(userInput))) &&
      (!statusInput ||
        (log.status && log.status.toLowerCase().includes(statusInput)))
    )
  })
  renderLogsTable(filtered)
}

function exportCSV() {
  const rows = [
    [
      "ID",
      "Timestamp",
      "Level",
      "Service",
      "Method",
      "Path",
      "StatusCode",
      "Message",
    ],
    ...allLogs.map((l) => [
      l._id,
      new Date(l.timestamp).toLocaleString(),
      l.level || "",
      l.service || "web",
      l.method || "",
      l.path || "",
      l.statusCode || "",
      l.message || l.details || "",
    ]),
  ]
  const csvContent =
    "data:text/csv;charset=utf-8," + rows.map((e) => e.join(",")).join("\n")
  const link = document.createElement("a")
  link.setAttribute("href", encodeURI(csvContent))
  link.setAttribute("download", "logs.csv")
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}

document.addEventListener("DOMContentLoaded", () => {
  fetchSummaryAndRender()
  fetchAndRenderLogs()

  document.getElementById("filter-user").addEventListener("input", applyFilters)
  document
    .getElementById("filter-status")
    .addEventListener("input", applyFilters)
  document.getElementById("download-csv").addEventListener("click", exportCSV)

  // Auto-refresh logs every 10 seconds
  setInterval(fetchAndRenderLogs, 10000)
})
