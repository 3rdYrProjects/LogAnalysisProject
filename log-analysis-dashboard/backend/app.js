const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const path = require("path");

const uploadRoutes = require("./ml/upload_route");
const logRoutes = require("./routes/logs");
const aiRoutes = require("./routes/ai");
const { router: authRouter } = require("./auth/routes");
const { authenticateToken } = require("./auth/middleware");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN || "http://localhost:4000",
    credentials: true,
  }),
);

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

app.use("/api", uploadRoutes);

/* ================= DATABASE ================= */
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/logAnalysis")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

/* ================= STATIC FILES ================= */
const frontendPath = path.join(__dirname, "../frontend");
app.use(express.static(frontendPath));

/* ================= ROUTES ================= */

// Public routes
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "landing.html"));
});

app.get("/dashboard", authenticateToken, (req, res) => {
  res.sendFile(path.join(frontendPath, "dashboard.html"));
});

app.use("/api/auth", authRouter);
app.use("/logs", authenticateToken, logRoutes);
app.use("/api/ai", authenticateToken, aiRoutes);

// Optional: Add ML health check route if not already in uploadRoutes
app.get("/api/ml-health", authenticateToken, async (req, res) => {
  try {
    const { checkMLHealth } = require("./ml/ml_service");
    const health = await checkMLHealth();
    res.json(health);
  } catch (err) {
    res.status(500).json({ models_loaded: false });
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
