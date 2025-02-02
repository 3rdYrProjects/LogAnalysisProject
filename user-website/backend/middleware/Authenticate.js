const jwt = require("jsonwebtoken")
const SECRET = "qur3ur83ut8u8" // Secret key used for signing the JWT

// Middleware to verify token
// Middleware to verify the token and get the user
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1] // Extract token from Authorization header
  if (!token) {
    return res.status(401).json({ error: "No token provided" })
  }

  try {
    const decoded = jwt.verify(token, SECRET)
    req.user = decoded // Attach decoded user info to request
    next()
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" })
  }
}

module.exports = verifyToken
