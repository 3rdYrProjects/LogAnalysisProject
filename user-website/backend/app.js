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
const logger = require("./js/winstonConfig")
const logToAnalysisAPI = require("./middleware/logtransfer")
dotenv.config()

const app = express()
const SECRET = process.env.JWT_SECRET || "qur3ur83ut8u8"

app.use(bodyParser.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(cors({ origin: "http://localhost:3000", credentials: true }))

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

const requestCounts = {}
const RATE_LIMIT = 100
const TIME_WINDOW = 60 * 1000

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

app.use((req, res, next) => {
  const token = req.cookies.authToken
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET)
      req.user = decoded // ✅ This is important!
      res.locals.isAuthenticated = true
      res.locals.username = decoded.username
    } catch (err) {
      req.user = null
      res.locals.isAuthenticated = false
    }
  } else {
    req.user = null
    res.locals.isAuthenticated = false
  }
  next()
})

let blogs = require("./data/blogs")

// Route to get all blogs
app.get("/blogs", (req, res) => {
  res.json(blogs)
})

app.delete("/delete/:id", async (req, res) => {
  const blogId = parseInt(req.params.id)
  const blog = blogs.find((b) => b.id === blogId)
  if (!blog) return res.status(404).send("Blog not found")

  blogs = blogs.filter((b) => b.id !== blogId)

  const logData = {
    userId: req.user?.userId || "unknown",
    activity: "Delete Blog",
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
    transferred: false,
    timestamp: new Date(),
    method: req.method,
    path: req.originalUrl,
    status: 200,
    level: "info",
    details: `Blog '${blog.title}' deleted by ${
      req.user?.username || "unknown"
    }`,
  }

  await Log.create(logData)
  logger.info(logData.details, logData)

  logToAnalysisAPI(logData)
  console.log("Deleted:", blog.title)
  res.status(200).send("Blog deleted successfully")
})

app.use("/auth", authRoutes)
app.use("/logs", logRoutes)

app.get("/", (req, res) => res.render("index"))
app.get("/signup", (req, res) => res.render("signup"))
app.get("/login", (req, res) => res.render("login"))

app.use((req, res) => res.status(404).render("404"))

const PORT = process.env.PORT || 3000
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
)
