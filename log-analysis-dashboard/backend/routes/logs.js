const express = require("express")
const mongoose = require("mongoose")
const router = express.Router()

// Log model definition
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
    })
  )

// Fetch all logs
router.get("/", async (req, res) => {
  try {
    const logs = await Log.find().populate("userId", "username") // Populate userId if needed
    res.status(200).json(logs)
  } catch (error) {
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
    res.status(200).json({ totalLogs, activities })
  } catch (error) {
    res.status(500).json({ error: "Error fetching summary" })
  }
})

// Create a log entry
router.post("/", async (req, res) => {
  try {
    const { userId, activity, details } = req.body
    const log = new Log({
      userId, // The user ID
      ipAddress: req.ip, // Capture IP address
      activity, // The activity (e.g., login, page visit)
      details, // Description of the activity
    })
    await log.save()
    res.status(201).send("Log created successfully.")
  } catch (err) {
    console.error(err)
    res.status(500).send("Error creating log.")
  }
})

module.exports = router
