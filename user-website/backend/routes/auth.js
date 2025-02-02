const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const User = require("../models/User")
const Log = require("../models/Log")
const logger = require("../js/winstonConfig")
const rateLimit = require("express-rate-limit")

const router = express.Router()
require("dotenv").config()

const SECRET = process.env.JWT_SECRET || "qur3ur83ut8u8"

// Function to get the client IP address
const getClientIp = (req) => {
  // First, check for the x-forwarded-for header for proxy
  const forwarded = req.headers["x-forwarded-for"]
  if (forwarded) {
    // The x-forwarded-for header may contain a list of IPs; the first one is the original client IP
    return forwarded.split(",")[0].trim()
  }
  // Fallback to remote address if no x-forwarded-for header found
  return (
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.ip ||
    "unknown"
  )
}

// Rate limiting for DoS detection (5 requests per minute from the same IP)
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
  handler: (req, res) => {
    const ip = getClientIp(req) // Get client IP for logging
    const logDetails = {
      userId: "unknown",
      activity: "Potential DoS Attack Detected",
      ipAddress: ip,
      userAgent: req.headers["user-agent"],
      details: `Too many requests detected from IP: ${ip}. Potential DoS attack.`,
      transferred: false,
      timestamp: new Date(),
      status: "attack in progress",
      requestId: req.id || "N/A", // Include request ID for traceability
    }

    // Log to the database and logger
    Log.create(logDetails)
      .then(() => {
        console.log("Log saved to database")
        logger.error("Potential DoS attack detected", logDetails)
      })
      .catch((err) => {
        console.error("Error saving log:", err)
        logger.error("Error saving log to database", { error: err.message })
      })

    // Log to winston logger
    logger.error("Dos Attack", {
      ipAddress: ip,
      userAgent: req.headers["user-agent"],
      details: "Potential DoS attack detected",
      activity: "Dos Attack",
      requestId: req.id || "N/A",
    })

    // Send response to the client
    res.status(429).json({
      message: "Too many requests from this IP, please try again later.",
    })
  },
})

// Apply the rate limiter to login and signup routes
router.use("/login", limiter)
router.use("/signup", limiter)

router.get("/signup", (req, res) => {
  res.render("signup")
})

// POST Signup Logic
router.post("/signup", async (req, res) => {
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
      ipAddress: getClientIp(req), // Log the correct client IP
      userAgent: req.headers["user-agent"],
      details: `User ${username} signed up successfully.`,
      transferred: false,
      timestamp: new Date(),
      requestId: req.id || "N/A",
    }

    await Log.create(logDetails)
    logger.info("User signed up", logDetails)

    const token = jwt.sign({ userId: user._id, username }, SECRET, {
      expiresIn: "1h",
    })

    // Set secure cookie with JWT token
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Ensure secure cookie only in production
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
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body

    const user = await User.findOne({ username })

    if (!user || !(await bcrypt.compare(password, user.password))) {
      // Log the failed login attempt with username, password (hashed), and IP address
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
