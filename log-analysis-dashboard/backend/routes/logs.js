const express = require("express");
const mongoose = require("mongoose");
const router = express.Router();

/* ================= LOG MODEL ================= */
const Log =
  mongoose.models.Log ||
  mongoose.model(
    "Log",
    new mongoose.Schema({
      timestamp: { type: Date, default: Date.now },
      userId: String,
      ipAddress: String,
      activity: String,
      details: String, // Full original log line
      status: Number,
      method: String,
      path: String,
      level: {
        type: String,
        enum: ["debug", "info", "warn", "error"],
        default: "info",
      },
    }),
  );

router.get("/", async (req, res) => {
  try {
    const logs = await Log.find().sort({ timestamp: -1 });
    res.status(200).json(logs);
  } catch (error) {
    console.error("Error fetching logs:", error);
    res.status(500).json({ error: "Error fetching logs" });
  }
});

router.get("/summary", async (req, res) => {
  try {
    const totalLogs = await Log.countDocuments();

    const activities = await Log.aggregate([
      { $group: { _id: "$activity", count: { $sum: 1 } } },
    ]);

    const statuses = await Log.aggregate([
      { $group: { _id: "$status", count: { $sum: 1 } } },
    ]);

    res.status(200).json({ totalLogs, activities, statuses });
  } catch (error) {
    console.error("Error fetching summary:", error);
    res.status(500).json({ error: "Error fetching summary" });
  }
});

module.exports = router;
