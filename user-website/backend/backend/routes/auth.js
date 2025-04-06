const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const User = require("../models/User")
const Log = require("../models/Log")
const logger = require("../js/winstonConfig")
const limiter = require("./dos_attack")
const detectSQLInjection = require("./sqlInjectionDetector")
const logToAnalysisAPI = require("../middleware/logtransfer")

const router = express.Router()
require("dotenv").config()

const SECRET = "qur3ur83ut8u8"

// Get IP address
const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"]
  if (forwarded) return forwarded.split(",")[0].trim()
  return (
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.ip ||
    "unknown"
  )
}

const logActivity = async (logData, level) => {
  const logEntry = { ...logData, level }
  try {
    await Log.create(logEntry)
    logger[level](logEntry.details, logEntry)
    logToAnalysisAPI(logEntry)
  } catch (err) {
    console.error("Logging failed:", err)
  }
}

// Rate limiters
router.use("/login", limiter)
router.use("/signup", limiter)

router.get("/signup", (req, res) => {
  res.render("signup")
})

router.post("/signup", detectSQLInjection, async (req, res) => {
  console.log("Request Body:", req.body)
  try {
    const { username, password } = req.body
    if (!username || !password)
      return res
        .status(400)
        .json({ error: "Username and password are required" })

    const existingUser = await User.findOne({ username })
    if (existingUser)
      return res.status(400).json({ error: "Username already exists" })

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = await User.create({ username, password: hashedPassword })

    const logData = {
      userId: user._id,
      activity: "User Signup",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
      service: "web",
      method: req.method,
      path: req.originalUrl,
      status: 201,
      details: `User ${username} signed up successfully.`,
    }
    await logActivity(logData, "info")

    const token = jwt.sign({ userId: user._id, username }, SECRET, {
      expiresIn: "1h",
    })
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })

    res.status(201).json({ details: "User registered successfully" })
  } catch (error) {
    const logData = {
      userId: "unknown",
      activity: "Signup Error",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
      service: "web",
      method: req.method,
      path: req.originalUrl,
      status: 500,
      details: error.message,
    }
    await logActivity(logData, "error")
    res.status(500).json({ error: "Error registering user" })
  }
})

router.get("/login", (req, res) => {
  res.render("login")
})

router.post("/login", detectSQLInjection, async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await User.findOne({ username })

    if (!user || !(await bcrypt.compare(password, user.password))) {
      const logData = {
        userId: "unknown",
        activity: "Login Failed",
        ipAddress: getClientIp(req),
        userAgent: req.headers["user-agent"],
        transferred: false,
        timestamp: new Date(),
        requestId: req.id || "N/A",
        service: "web",
        method: req.method,
        path: req.originalUrl,
        status: 400,
        details: `Failed login attempt for username: ${username}`,
      }
      await logActivity(logData, "warn")

      return res.status(400).json({ error: "Invalid username or password" })
    }

    const token = jwt.sign({ userId: user._id, username }, SECRET, {
      expiresIn: "1h",
    })
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })

    const logData = {
      userId: user._id,
      activity: "User Login",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
      service: "web",
      method: req.method,
      path: req.originalUrl,
      status: 200,
      details: `User ${username} logged in successfully.`,
    }
    await logActivity(logData, "info")

    res.redirect("/")
  } catch (error) {
    const logData = {
      userId: "unknown",
      activity: "Login Error",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
      service: "web",
      method: req.method,
      path: req.originalUrl,
      status: 500,
      details: error.message,
    }
    await logActivity(logData, "error")
    res.status(500).json({ error: "Error logging in" })
  }
})

router.get("/logout", async (req, res) => {
  try {
    const token = req.cookies.authToken
    if (!token) return res.status(400).json({ error: "No token found" })

    const decoded = jwt.verify(token, SECRET)

    const logData = {
      userId: decoded.userId,
      activity: "User Logout",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
      service: "web",
      method: req.method,
      path: req.originalUrl,
      status: 200,
      details: `User ${decoded.username} logged out successfully.`,
    }
    await logActivity(logData, "info")

    res.clearCookie("authToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })
    res.redirect("/auth/login")
  } catch (error) {
    const logData = {
      userId: "unknown",
      activity: "Logout Error",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
      service: "web",
      method: req.method,
      path: req.originalUrl,
      status: 500,
      details: error.message,
    }
    await logActivity(logData, "error")
    res.status(500).json({ error: "Error logging out" })
  }
})

module.exports = router
