const winston = require("winston")
const axios = require("axios")

const logTransport = new winston.transports.Http({
  host: "localhost", // Ensure this is correct
  port: 4000, // Check if your backend is listening on this port
  path: "/logs",
  level: "info",
  headers: { "Content-Type": "application/json" },
  formatter: (log) => {
    console.log("Sending log to backend:", log) // Debugging line to see the log being sent
    return JSON.stringify({
      userId: log.userId,
      activity: log.activity,
      details: log.details,
      timestamp: log.timestamp,
    })
  },
})

const logger = winston.createLogger({
  level: "info",
  transports: [logTransport],
})

module.exports = logger
