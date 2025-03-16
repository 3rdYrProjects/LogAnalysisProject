const axios = require("axios")

const logToAnalysisAPI = async (logDetails) => {
  try {
    const logAnalysisAPIUrl =
      "https://f62a-2405-201-6817-68db-f0b3-e0ed-8dd1-65cb.ngrok-free.app/logs"
    const response = await axios.post(logAnalysisAPIUrl, logDetails)

    if (response.status === 200) {
      console.log("Log successfully sent to Log Analysis API.")
    }
  } catch (error) {
    console.error("Failed to send log to Log Analysis API:", error.message)
  }
}

module.exports = logToAnalysisAPI
