const express = require("express")
const mongoose = require("mongoose")
const router = express.Router()
const fetch = require("node-fetch")

const Log =
  mongoose.models.Log ||
  mongoose.model(
    "Log",
    new mongoose.Schema({
      timestamp: { type: Date, default: Date.now },
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      ipAddress: { type: String },
      activity: { type: String },
      details: { type: String },
    })
  )

router.get("/", async (req, res) => {
  try {
    const logs = await Log.find()
      .populate("userId", "username")
      .sort({ timestamp: -1 })
    res.status(200).json(logs)
  } catch (error) {
    console.error("Error fetching logs:", error.message)
    res.status(500).json({ error: "Error fetching logs" })
  }
})

router.post("/", async (req, res) => {
  try {
    const { username, activity, details } = req.body

    if (!username || !activity || !details) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const user = await mongoose.model("User").findOne({ username })
    if (!user) {
      return res
        .status(400)
        .json({ error: "Invalid username or user not found" })
    }

    // Create and save the log entry
    const log = new Log({
      userId: user._id,
      ipAddress: req.headers["x-forwarded-for"] || req.ip, // Use x-forwarded-for if behind proxy
      activity,
      details,
    })

    console.log("Log to be saved:", log)
    await log.save()

    // Send log data to log analysis website
    const response = await sendLogToAnalysis(log)
    if (response.ok) {
      console.log("Log sent to log analysis website successfully.")
    } else {
      console.error("Failed to send log to log analysis website.")
    }

    res.status(201).send("Log created successfully.")
  } catch (err) {
    console.error("Error creating log:", err.message)
    res.status(500).send("Error creating log.")
  }
})

// Function to send logs to the log analysis website

module.exports = router
