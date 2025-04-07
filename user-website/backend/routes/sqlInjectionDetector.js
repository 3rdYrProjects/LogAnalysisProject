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
      const logDetails = {
        level: "warn",
        method: req.method,
        path: req.originalUrl,
        status: 403,
        details: `SQL Injection detected: ${injectedValue}`,
        ipAddress:
          req.headers["x-forwarded-for"] || req.connection.remoteAddress,
        userAgent: req.headers["user-agent"],
        timestamp: new Date(),
      }

      console.log("🔴 SQL Injection Attempt Detected:", logDetails)

      await Log.create(logDetails)
      logToAnalysisAPI(logDetails)

      return res.status(403).redirect("/login")
    }

    next()
  } catch (error) {
    console.error("❌ SQL Injection Middleware Error:", error.details)

    return res.status(500).json({ error: "Internal Server Error" })
  }
}

module.exports = detectSQLInjection
