const API_BASE = "http://localhost:4000" // Assuming your log analysis backend is running on port 4000

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Fetch Summary of logs
    const summaryResponse = await fetch(`${API_BASE}/logs/summary`)
    const summaryData = await summaryResponse.json()

    document.getElementById(
      "total-logs"
    ).textContent = `Total Logs: ${summaryData.totalLogs}`

    // Activity Summary
    const activitySummary = document.getElementById("activity-summary")
    summaryData.activities.forEach((activity) => {
      const li = document.createElement("li")
      li.textContent = `${activity._id}: ${activity.count}`
      activitySummary.appendChild(li)
    })

    // Fetch All Logs
    const logsResponse = await fetch(`${API_BASE}/logs`)
    const logsData = await logsResponse.json()

    const logsTable = document.getElementById("logs-table")
    logsData.forEach((log) => {
      const row = document.createElement("tr")
      row.innerHTML = `
        <td>${new Date(log.timestamp).toLocaleString()}</td>
        <td>${log.userId || "N/A"}</td>
        <td>${log.ipAddress || "N/A"}</td>
        <td>${log.activity}</td>
        <td>${log.details}</td>
      `
      logsTable.appendChild(row)
    })
  } catch (error) {
    console.error("Error loading data:", error)
  }
})
