const API_BASE = "http://localhost:4000";

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Fetch Summary of logs
    const summaryResponse = await fetch(`${API_BASE}/logs/summary`);
    const summaryData = await summaryResponse.json();

    document.getElementById("total-logs").textContent = `Total Logs: ${summaryData.totalLogs}`;

    // Chart: Activity Summary
    const activityChart = document.getElementById("activity-chart").getContext("2d");
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
    });

    // Chart: Status Summary
    const statusChart = document.getElementById("status-chart").getContext("2d");
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
    });

    // Fetch All Logs
    const logsResponse = await fetch(`${API_BASE}/logs`);
    const logsData = await logsResponse.json();

    const logsTable = document.getElementById("logs-table");
    logsData.forEach((log) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="p-2">${new Date(log.timestamp).toLocaleString()}</td>
        <td class="p-2">${log.userId || "N/A"}</td>
        <td class="p-2">${log.ipAddress || "N/A"}</td>
        <td class="p-2">${log.activity}</td>
        <td class="p-2">${log.details}</td>
        <td class="p-2">${log.status || "N/A"}</td>
        <td class="p-2">${log.transferred ? "Yes" : "No"}</td>
      `;
      logsTable.appendChild(row);
    });
  } catch (error) {
    console.error("Error loading data:", error);
  }
});
