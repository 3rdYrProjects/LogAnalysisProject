const mongoose = require("mongoose")

const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  activity: String,
  ipAddress: String,
  details: String,
  timestamp: { type: Date, default: Date.now },
  transferred: { type: Boolean, default: false },
})

module.exports = mongoose.model("Log", logSchema)
