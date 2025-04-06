const express = require("express")
const mongoose = require("mongoose")
const router = express.Router()

// ✅ Updated Schema to include method and path
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
      status: { type: String, default: "unknown" },
      transferred: { type: Boolean, default: false },
      method: { type: String }, // ✅ Added
      path: { type: String }, // ✅ Added
    })
  )

// Fetch all logs
router.get("/", async (req, res) => {
  try {
    const logs = await Log.find()
    res.status(200).json(logs)
  } catch (error) {
    console.error("Error fetching logs:", error)
    res.status(500).json({ error: "Error fetching logs" })
  }
})

// Summary route
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

// ✅ Create log with method and path
router.post("/", async (req, res) => {
  try {
    const {
      userId,
      activity,
      details,
      status = "unknown",
      transferred = false,
      method,
      path,
    } = req.body

    const log = new Log({
      userId,
      ipAddress: req.ip,
      activity,
      details,
      status,
      transferred,
      method: method || req.method, // fallback if not provided
      path: path || req.originalUrl, // fallback if not provided
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
