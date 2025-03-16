const Log = require("../models/Log")
const logToAnalysisAPI = require("../middleware/logtransfer")

const sqlKeywords = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "DROP",
  "UNION",
  "ALTER",
  "EXEC",
  "OR 1=1",
  "' OR '1'='1",
  "--",
  ";--",
  "/*",
  "*/",
  "' OR ''='",
]

const detectSQLInjection = async (req, res, next) => {
  try {
    let isSQLInjection = false
    let injectedValue = ""

    for (const key in req.body) {
      if (typeof req.body[key] === "string") {
        const value = req.body[key].toUpperCase()
        if (sqlKeywords.some((keyword) => value.includes(keyword))) {
          isSQLInjection = true
          injectedValue = req.body[key]
          break
        }
      }
    }

    if (isSQLInjection) {
      const ipAddress =
        req.headers["x-forwarded-for"] || req.connection.remoteAddress

      const logDetails = {
        userId: req.user ? req.user._id : "unknown",
        activity: "SQL Injection Attempt",
        ipAddress: ipAddress,
        userAgent: req.headers["user-agent"],
        details: `SQL Injection detected: ${injectedValue}`,
        transferred: false,
        timestamp: new Date(),
        status: "attack detected",
      }

      console.log("🔴 SQL Injection Attempt Detected:", logDetails) // Debugging log

      if (!Log || typeof Log.create !== "function") {
        console.error("❌ Log model is not defined correctly.")
        return res.status(500).json({ error: "Logging system error." })
      }

      logToAnalysisAPI(logDetails)

      return res.status(403).json({ error: "SQL Injection attempt detected!" })
    }

    next() // Proceed if no SQL injection detected
  } catch (error) {
    console.error("❌ SQL Injection Middleware Error:", error.message) // Log the full error
    console.error(error.stack) // Show detailed error stack

    return res.status(500).json({ error: "Internal Server Error" })
  }
}

module.exports = detectSQLInjection
