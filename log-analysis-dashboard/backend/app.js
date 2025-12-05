const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const path = require("path");
const logRoutes = require("./routes/logs");
const apiKey = require("./routes/ai");

// Initialize Express App
const app = express();
app.use(cors());
app.use(express.json()); // Parse incoming JSON

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost:27017/logAnalysis", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB for Log Analysis Dashboard"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Serve Frontend Static Files (for Single Page Apps)
app.use(express.static(path.join(__dirname, "../frontend")));

// API Routes
app.use("/logs", logRoutes);
app.use("/api/ai", apiKey);

// Catch-All Route (For SPA routing)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

const PORT = 4000;
app.listen(PORT, () =>
  console.log(`Log Analysis API running at http://localhost:${PORT}`)
);
