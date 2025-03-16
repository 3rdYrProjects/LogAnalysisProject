const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const path = require("path")
const app = express()
const port = 3000

app.use(express.urlencoded({ extended: true }))
app.use(express.json())

mongoose
  .connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err))

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")))
app.get("/signup", (req, res) =>
  res.sendFile(path.join(__dirname, "signup.html"))
)
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "login.html"))
)
app.get("/home", (req, res) => res.sendFile(path.join(__dirname, "home.html")))
app.get("/Dashboard", (req, res) =>
  res.sendFile(path.join(__dirname, "Dashboard.html"))
)
app.get("/ViewTransaction", (req, res) =>
  res.sendFile(path.join(__dirname, "ViewTransaction.html"))
)
app.get("/Income", (req, res) =>
  res.sendFile(path.join(__dirname, "Income.html"))
)
app.get("/Expenses", (req, res) =>
  res.sendFile(path.join(__dirname, "Expenses.html"))
)

app.post("/users", async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username || !password) {
      return res.status(400).send("Username and password are required")
    }

    const existingUser = await User.findOne({ username })
    if (existingUser) {
      return res.status(400).send("User already exists")
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const newUser = new User({ username, password: hashedPassword })
    await newUser.save()

    res.status(201).send("User registered successfully")
  } catch (error) {
    res.status(500).send("Error registering user")
  }
})

app.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username || !password) {
      return res.status(400).send("Username and password are required")
    }

    const user = await User.findOne({ username })
    if (!user) {
      return res.status(400).send("Cannot find user")
    }

    const passwordMatch = await bcrypt.compare(password, user.password)
    if (passwordMatch) {
      res.send("Login successful")
    } else {
      res.status(401).send("Invalid password")
    }
  } catch (error) {
    res.status(500).send("Internal Server Error")
  }
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
  console.log("Listening for requests...")
})
