const mongoose = require("mongoose")

const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  activity: String,
  ipAddress: String,
  details: String,
  timestamp: { type: Date, default: Date.now },
  transferred: { type: Boolean, default: false },
})

const Log = mongoose.model("Log", logSchema)

module.exports = Log
