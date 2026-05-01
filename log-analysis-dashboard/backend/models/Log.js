// models/Log.js  (or wherever you define it)
const mongoose = require("mongoose");

const logSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  userId: String,
  ipAddress: String,
  activity: String,
  details: String,
  status: Number,
  method: String,
  path: String,
  level: {
    type: String,
    enum: ["debug", "info", "warn", "error"],
    default: "info",
  },
  transferred: { type: Boolean, default: false },
});

module.exports = mongoose.model("Log", logSchema);
