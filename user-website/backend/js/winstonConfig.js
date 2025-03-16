const winston = require("winston")
const axios = require("axios")

const logTransport = new winston.transports.Http({
  host: "localhost",
  port: 4000,
  path: "/logs",
  level: "info",
  headers: { "Content-Type": "application/json" },
  formatter: (log) => {
    console.log("Sending log to backend:", log)
    return JSON.stringify({
      _id: log._id.toString(),
      userId,
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
