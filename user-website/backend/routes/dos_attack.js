const rateLimit = require("express-rate-limit")
const Log = require("../models/Log")
const logger = require("../js/winstonConfig")
const logToAnalysisAPI = require("../middleware/logtransfer")

const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"]
  if (forwarded) {
    return forwarded.split(",")[0].trim()
  }

  return (
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.ip ||
    "unknown"
  )
}

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // Limit each IP to 5 requests per minute
  message: "Too many requests from this IP, please try again later.",
  handler: (req, res) => {
    const ip = getClientIp(req)
    const logDetails = {
      userId: "unknown",
      activity: "Potential DoS Attack Detected",
      ipAddress: ip,
      userAgent: req.headers["user-agent"],
      details: `Too many requests detected from IP: ${ip}. Potential DoS attack.`,
      transferred: false,
      timestamp: new Date(),
      status: "attack in progress",
      requestId: req.id || "N/A",
    }

    Log.create(logDetails)
      .then(() => {
        console.log("Log saved to database")
        logger.error("Potential DoS attack detected", logDetails)

        logToAnalysisAPI(logDetails)
      })
      .catch((err) => {
        console.error("Error saving log:", err)
        logger.error("Error saving log to database", { error: err.message })
      })

    logger.error("Dos Attack", {
      ipAddress: ip,
      userAgent: req.headers["user-agent"],
      details: "Potential DoS attack detected",
      activity: "Dos Attack",
      requestId: req.id || "N/A",
    })

    res.status(429).json({
      message: `Too many requests from this IP ${ip}, please try again later.`,
    })
  },
})

module.exports = limiter
