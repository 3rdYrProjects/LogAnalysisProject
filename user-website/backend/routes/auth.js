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

const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"]
  if (forwarded) {
    return forwarded.split(",")[0].trim()
  }

  return (
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.ip ||
    "unknown"
  )
}

router.use("/login", limiter)
router.use("/signup", limiter)

router.get("/signup", (req, res) => {
  res.render("signup")
})

// POST Signup Logic
router.post("/signup", detectSQLInjection, async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" })
    }

    const existingUser = await User.findOne({ username })
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = await User.create({ username, password: hashedPassword })

    const logDetails = {
      userId: user._id,
      activity: "User Signup",
      ipAddress: getClientIp(req),
      userAgent: req.headers["user-agent"],
      details: `User ${username} signed up successfully.`,
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
    }

    await Log.create(logDetails)
    logger.info("User signed up", logDetails)

    // Send the log to Log Analysis API
    logToAnalysisAPI(logDetails)

    const token = jwt.sign({ userId: user._id, username }, SECRET, {
      expiresIn: "1h",
    })

    // Set secure cookie with JWT token
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })

    res.status(201).json({ message: "User registered successfully" })
  } catch (error) {
    logger.error("Signup error", {
      error: error.message,
      userAgent: req.headers["user-agent"],
      requestId: req.id || "N/A",
    })
    res.status(500).json({ error: "Error registering user" })
  }
})

router.get("/login", (req, res) => {
  res.render("login")
})

// POST Login Logic
router.post("/login", detectSQLInjection, async (req, res) => {
  try {
    const { username, password } = req.body

    const user = await User.findOne({ username })

    if (!user || !(await bcrypt.compare(password, user.password))) {
      logger.error("Failed login attempt", {
        username: username,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        details: "Invalid username or password",
        activity: "Failed Login Attempt",
        requestId: req.id || "N/A",
      })

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

    const logDetails = {
      userId: user._id,
      activity: "User Login",
      ipAddress: getClientIp(req), // Log the correct client IP
      userAgent: req.headers["user-agent"],
      details: `User ${username} logged in successfully.`,
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
    }

    await Log.create(logDetails)
    logger.info("User logged in", logDetails)

    // Send the log to Log Analysis API
    logToAnalysisAPI(logDetails)

    res.redirect("/")
  } catch (error) {
    logger.error("Login error", {
      error: error.message,
      userAgent: req.headers["user-agent"],
      requestId: req.id || "N/A",
    })
    res.status(500).json({ error: "Error logging in" })
  }
})

// POST Logout Logic
router.get("/logout", async (req, res) => {
  try {
    const token = req.cookies.authToken
    if (!token) {
      return res.status(400).json({ error: "No token found" })
    }

    const decoded = jwt.verify(token, SECRET)

    const logDetails = {
      userId: decoded.userId,
      activity: "User Logout",
      ipAddress: getClientIp(req), // Log the correct client IP
      userAgent: req.headers["user-agent"],
      details: `User ${decoded.username} logged out successfully.`,
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
    }

    await Log.create(logDetails)
    logger.info("User logged out", logDetails)

    // Send the log to Log Analysis API
    logToAnalysisAPI(logDetails)

    res.clearCookie("authToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })
    res.redirect("/auth/login")
  } catch (error) {
    logger.error("Logout error", {
      error: error.message,
      userAgent: req.headers["user-agent"],
      requestId: req.id || "N/A",
    })
    res.status(500).json({ error: "Error logging out" })
  }
})

module.exports = router
