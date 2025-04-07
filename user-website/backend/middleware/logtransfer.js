const axios = require("axios")

const logToAnalysisAPI = async (logDetails) => {
  try {
    const logAnalysisAPIUrl = "http://localhost:4000/logs"

    const response = await axios.post(logAnalysisAPIUrl, logDetails, {
      headers: { "Content-Type": "application/json" },
    })

    if (response.status === 200) {
      console.log("Log successfully sent to Log Analysis API.")
    } else {
      console.error("Failed to send log. Status:", response.status)
    }
  } catch (error) {
    console.error("Failed to send log to Log Analysis API:", error.message)
  }
}

module.exports = logToAnalysisAPI
