const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const User = require("../models/User")
const Log = require("../models/Log")

const router = express.Router()
const SECRET = "qur3ur83ut8u8"

// GET Signup Page
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
      ipAddress: req.ip,
      details: `User ${username} signed up successfully.`,
    }

    try {
      await Log.create(logDetails)
      console.log("Signup log saved:", logDetails)
    } catch (err) {
      console.error("Failed to save signup log:", err)
    }
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
    })

    res.status(201).json({ message: "User registered successfully" })
  } catch (error) {
    console.error("Signup error:", error)
    res.status(500).json({ error: "Error registering user" })
  }
})

// GET Login Page
router.get("/login", (req, res) => {
  res.render("login")
})

// POST Login Logic
// POST Login Logic
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await User.findOne({ username })

    if (!user)
      return res.status(404).json({ error: "Invalid username or password" })

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch)
      return res.status(400).json({ error: "Invalid username or password" })

    const token = jwt.sign({ userId: user._id, username }, SECRET, {
      expiresIn: "1h",
    })

    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })

    // Add log with `transferred: false`
    const logDetails = {
      userId: user._id,
      activity: "User Login",
      ipAddress: req.ip,
      details: `User ${username} logged in successfully.`,
      transferred: false, // Mark as not transferred
    }

    try {
      await Log.create(logDetails)
      console.log("Login log saved:", logDetails)
    } catch (err) {
      console.error("Failed to save login log:", err)
    }

    res.redirect("/")
  } catch (error) {
    console.error("Login error:", error.message)
    res.status(500).json({ error: "Error logging in" })
  }
})

// POST Logout Logic
// POST Logout Logic
router.get("/logout", async (req, res) => {
  try {
    const token = req.cookies.authToken
    if (!token) {
      return res.status(400).json({ error: "No token found" })
    }

    const decoded = jwt.verify(token, SECRET)

    // Add log with `transferred: false`, including the username
    const logDetails = {
      userId: decoded.userId,
      activity: "User Logout",
      ipAddress: req.ip,
      details: `User ${decoded.username} logged out successfully.`, // Include username in log
      transferred: false,
    }

    try {
      await Log.create(logDetails)
      console.log("Logout log saved:", logDetails)
    } catch (err) {
      console.error("Failed to save logout log:", err)
    }

    res.clearCookie("authToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    })

    res.redirect("/auth/login")
  } catch (error) {
    console.error("Logout error:", error)
    res.status(500).json({ error: "Error logging out" })
  }
})

module.exports = router
