const mongoose = require("mongoose")

const logSchema = new mongoose.Schema({
  userId: { type: String, default: "unknown" },
  activity: String,
  ipAddress: String,
  userAgent: String,
  details: String,
  transferred: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
  status: String,
})

module.exports = mongoose.model("Log", logSchema)
