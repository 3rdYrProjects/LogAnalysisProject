const express = require("express")
const mongoose = require("mongoose")
const router = express.Router()

// Log model definition with added fields: status and transferred
const Log =
  mongoose.models.Log ||
  mongoose.model(
    "Log",
    new mongoose.Schema({
      timestamp: { type: Date, default: Date.now },
      userId: { type: String },
      ipAddress: { type: String },
      activity: { type: String },
      details: { type: String },
      status: { type: String, default: "unknown" }, // New field for status
      transferred: { type: Boolean, default: false }, // New field for transferred status
    })
  )

// Fetch all logs with added fields: status and transferred
router.get("/", async (req, res) => {
  try {
    const logs = await Log.find().populate("userId", "username")
    res.status(200).json(logs)
  } catch (error) {
    console.error("Error fetching logs:", error)
    res.status(500).json({ error: "Error fetching logs" })
  }
})

// Summary of logs
router.get("/summary", async (req, res) => {
  try {
    const totalLogs = await Log.countDocuments()
    const activities = await Log.aggregate([
      { $group: { _id: "$activity", count: { $sum: 1 } } },
    ])
    const statuses = await Log.aggregate([
      { $group: { _id: "$status", count: { $sum: 1 } } },
    ])
    res.status(200).json({ totalLogs, activities, statuses })
  } catch (error) {
    console.error("Error fetching summary:", error)
    res.status(500).json({ error: "Error fetching summary" })
  }
})

// Create a log entry with status and transferred fields
router.post("/", async (req, res) => {
  try {
    const {
      userId,
      activity,
      details,
      status = "unknown",
      transferred = false,
    } = req.body
    const log = new Log({
      userId, // The user ID
      ipAddress: req.ip, // Capture IP address
      activity, // The activity (e.g., login, page visit)
      details, // Description of the activity
      status, // Status of the log (e.g., "active", "resolved", etc.)
      transferred, // Whether the log entry has been transferred or not
    })
    await log.save()
    console.log(`Log created: ${activity} for user ${userId}`)
    res.status(201).send("Log created successfully.")
  } catch (err) {
    console.error("Error creating log:", err)
    res.status(500).send("Error creating log.")
  }
})

module.exports = router
// Paginated Logs
router.get("/paginated", async (req, res) => {
  const { page = 1, limit = 10 } = req.query; // Default values
  try {
    const logs = await Log.find()
      .skip((page - 1) * limit)
      .limit(Number(limit));
    const total = await Log.countDocuments();
    res.status(200).json({ logs, total, page, totalPages: Math.ceil(total / limit) });
  } catch (error) {
    console.error("Error fetching paginated logs:", error);
    res.status(500).json({ error: "Error fetching paginated logs" });
  }
});
