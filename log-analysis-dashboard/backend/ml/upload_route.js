const express = require("express");
const multer = require("multer");
const mongoose = require("mongoose");

const router = express.Router();

const { authenticateToken } = require("../auth/middleware");
const {
  analyzeLogs,
  checkMLHealth,
  normalizeLogs,
} = require("../ml/ml_service");

/* ================= MODEL ================= */
const Log =
  mongoose.models.Log ||
  mongoose.model(
    "Log",
    new mongoose.Schema({
      timestamp: { type: Date, default: Date.now },
      userId: String,
      ipAddress: String,
      activity: String,
      details: String,
      status: Number,
      method: String,
      path: String,
      level: String,
    }),
  );

/* ================= MULTER ================= */
const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype.startsWith("text/") ||
      file.originalname.match(/.(log|txt|json)$/i)
    ) {
      cb(null, true);
    } else {
      cb(new Error("Only .log, .txt, .json files allowed"), false);
    }
  },
});

/* ================= APACHE PARSER ================= */
function parseApacheLog(line) {
  const regex =
    /^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+HTTP\/\d\.\d"\s+(\d+)/;

  const match = line.match(regex);

  if (!match) {
    console.log("❌ Failed to parse:", line); // DEBUG
    return null;
  }

  return {
    ip: match[1],
    userId: "",
    timestamp: new Date(), // can improve later
    method: match[3],
    path: match[4],
    status: parseInt(match[5], 10),
    details: line.trim(),
  };
}

/* ================= PARSER ================= */
function parseLogBuffer(buffer) {
  if (!buffer || buffer.length === 0) return [];

  const content = buffer.toString("utf-8").trim();

  // ✅ TRY JSON FIRST
  if (content.startsWith("[")) {
    try {
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) return parsed;
    } catch {}
  }

  const lines = content.split("\n").filter((l) => l.trim() !== "");

  // ✅ REMOVE GARBAGE LINES (like "z")
  const cleanLines = lines.filter((line) => /^\d+.\d+.\d+.\d+/.test(line));

  // ✅ APACHE PARSE
  const apacheLogs = cleanLines.map(parseApacheLog).filter(Boolean);

  if (apacheLogs.length > 0) {
    console.log(`✅ Parsed ${apacheLogs.length} Apache logs`);
    return apacheLogs;
  }

  // ✅ FALLBACK
  return cleanLines.map((line) => ({
    timestamp: new Date(),
    ip: "unknown",
    userId: "",
    method: "UNKNOWN",
    path: "/",
    status: 200,
    details: line.trim(),
  }));
}

/* ================= ROUTE ================= */
router.post(
  "/upload",
  authenticateToken,
  upload.single("logfile"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const health = await checkMLHealth();
      if (!health?.models_loaded) {
        return res.status(503).json({ error: "ML service is not ready" });
      }

      const rawLogs = parseLogBuffer(req.file.buffer);

      if (rawLogs.length === 0) {
        return res.status(400).json({ error: "No valid logs parsed" });
      }

      /* ================= SAVE TO DB (CORRECT DATA) ================= */
      const processedLogs = rawLogs.map((log) => ({
        timestamp: log.timestamp || new Date(),
        userId: log.userId || "anonymous",

        ipAddress: log.ip || log.ipAddress || "unknown",

        activity: "Log Entry",

        details: log.details || "",

        status: Number(log.status) || 200,

        method: log.method || "GET",

        path: log.path || "/",

        level:
          log.status >= 500 ? "error" : log.status >= 400 ? "warn" : "info",
      }));

      await Log.insertMany(processedLogs, { ordered: false });

      /* ================= ML ================= */
      const normalizedLogs = normalizeLogs(rawLogs);
      const analysis = await analyzeLogs(normalizedLogs);

      return res.json({
        success: true,
        logsInserted: processedLogs.length,
        parsed: rawLogs.length,
        file: req.file.originalname,
        analysis,
      });
    } catch (err) {
      console.error("Upload Error:", err);

      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: "File too large (max 50MB)" });
      }

      res.status(500).json({ error: err.message });
    }
  },
);

module.exports = router;
