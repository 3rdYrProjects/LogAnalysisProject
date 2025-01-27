const mongoose = require("mongoose")

// Define the schema for logging user activities
const logSchema = new mongoose.Schema(
  {
    timestamp: { type: Date, default: Date.now }, // When the activity was logged
    userId: { type: String, required: true }, // User ID (could be username or any unique identifier)
    ipAddress: { type: String }, // The IP address from which the activity was performed
    activity: { type: String, required: true }, // Activity type (e.g., "User Login", "Page Visit", "Failed Login")
    details: { type: String }, // Additional details (e.g., "User logged in successfully")
  },
  { timestamps: true } // Automatically add createdAt and updatedAt fields
)

// Create and export the Log model
const Log = mongoose.model("Log", logSchema)
module.exports = Log
