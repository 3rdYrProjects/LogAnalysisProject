const mongoose = require("mongoose")

const logSchema = new mongoose.Schema({
  userId: { type: String, default: "unknown" },
  activity: { type: String },
  ipAddress: { type: String },
  userAgent: { type: String },
  details: { type: String },
  transferred: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
  requestId: { type: String, default: "N/A" },
  method: { type: String },
  path: { type: String },
  status: { type: Number },
  level: {
    type: String,
    enum: ["debug", "info", "warn", "error", "fatal"],
    default: "info",
  },
})

module.exports = mongoose.model("Log", logSchema)
