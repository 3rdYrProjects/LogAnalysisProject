const express = require("express")
const mongoose = require("mongoose")
const bodyParser = require("body-parser")
const path = require("path")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const cors = require("cors")
const dotenv = require("dotenv")
const Log = require("./models/Log")
const authRoutes = require("./routes/auth")
const logRoutes = require("./routes/logs")
const commentRoutes = require("./routes/commentRoutes")

dotenv.config() // Load environment variables

const app = express()
const SECRET = process.env.JWT_SECRET || "qur3ur83ut8u8"

// Middleware
app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(cors({ origin: "http://localhost:3000", credentials: true }))

// View Engine Setup
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))
app.use(express.static(path.join(__dirname, "public")))

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost:27017/userWebsite", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err))

// Rate-Limiting Middleware (DoS Detection)
const requestCounts = {}
const RATE_LIMIT = 100
const TIME_WINDOW = 60 * 1000 // 1 minute

app.use((req, res, next) => {
  const ip = req.ip
  const currentTime = Date.now()

  if (!requestCounts[ip]) requestCounts[ip] = []
  requestCounts[ip] = requestCounts[ip].filter(
    (timestamp) => timestamp > currentTime - TIME_WINDOW
  )
  requestCounts[ip].push(currentTime)

  if (requestCounts[ip].length > RATE_LIMIT) {
    Log.create({
      activity: "DoS Attack Attempt",
      details: `Possible DoS attack detected from IP: ${ip}.`,
      ipAddress: ip,
    }).catch((err) => console.error("Failed to log DoS attempt:", err))

    return res
      .status(429)
      .json({ error: "Too many requests. Try again later." })
  }

  next()
})

// Authentication Middleware
app.use((req, res, next) => {
  const token = req.cookies.authToken
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET)
      res.locals.isAuthenticated = true
      res.locals.username = decoded.username
    } catch (err) {
      res.locals.isAuthenticated = false
    }
  } else {
    res.locals.isAuthenticated = false
  }
  next()
})

// Routes
app.use("/auth", authRoutes)
app.use("/logs", logRoutes)
// app.use("/blog", blogRoutes)
app.use("/comments", commentRoutes)

// Pages
app.get("/", (req, res) => res.render("index"))
app.get("/signup", (req, res) => res.render("signup"))
app.get("/login", (req, res) => res.render("login"))

// 404 Page
app.use((req, res) => res.status(404).render("404"))

const PORT = process.env.PORT || 3000
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
)
