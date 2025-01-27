const express = require("express")
const mongoose = require("mongoose")
const bodyParser = require("body-parser")
const path = require("path")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const cors = require("cors")
const Log = require("./models/Log")
const verifyToken = require("./middleware/Authenticate")

const authRoutes = require("./routes/auth")
const logRoutes = require("./routes/logs")

const app = express()

// Secret Key for JWT
const SECRET = "qur3ur83ut8u8" // Replace with your actual secret key

// Middleware to parse JSON and URL-encoded bodies
app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(cors())

// View Engine Setup
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))

app.use(express.static(path.join(__dirname, "public")))

mongoose
  .connect("mongodb://localhost:27017/userWebsite", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err))

// Track user requests
const requestCounts = {}

// Middleware for rate-limiting and DoS detection
const RATE_LIMIT = 100 // Max requests per minute
const TIME_WINDOW = 60 * 1000 // 1 minute in milliseconds

app.use((req, res, next) => {
  const ip = req.ip // Use IP to track requests
  const currentTime = Date.now()

  if (!requestCounts[ip]) {
    requestCounts[ip] = []
  }

  // Filter out requests older than TIME_WINDOW
  requestCounts[ip] = requestCounts[ip].filter(
    (timestamp) => timestamp > currentTime - TIME_WINDOW
  )

  // Add current request timestamp
  requestCounts[ip].push(currentTime)

  if (requestCounts[ip].length > RATE_LIMIT) {
    // Possible DoS attack detected
    const logDetails = {
      activity: "DoS Attack Attempt",
      details: `Possible DoS attack detected from IP: ${ip}. Exceeded ${RATE_LIMIT} requests in 1 minute.`,
      ipAddress: ip,
    }

    // Log the detected DoS attempt
    Log.create(logDetails)
      .then(() => console.log("DoS attempt logged"))
      .catch((err) => console.error("Failed to log DoS attempt:", err))

    return res
      .status(429)
      .json({ error: "Too many requests. Please try again later." })
  }

  next()
})

// Middleware to check user authentication
app.use((req, res, next) => {
  const token = req.cookies.authToken
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET)
      res.locals.isAuthenticated = true
      res.locals.username = decoded.username
      console.log("User authenticated:", decoded)
    } catch (err) {
      res.locals.isAuthenticated = false
      console.error("Token verification failed:", err.message)
    }
  } else {
    res.locals.isAuthenticated = false
    console.log("No token found in cookies.")
  }
  next()
})

// Routes
app.use("/auth", authRoutes)
app.use("/logs", logRoutes)

// Home Page
app.get("/blog", verifyToken, (req, res) => {
  res.render("index")
})
app.get("/", verifyToken, (req, res) => {
  res.render("index")
})
app.get("/signup", (req, res) => res.render("signup"))

app.get("/login", (req, res) => res.render("login"))

app.use((req, res) => res.status(404).render("404"))

const PORT = 3000
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
)
