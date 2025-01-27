const jwt = require("jsonwebtoken")
function verifyToken(req, res, next) {
  const token = req.header("Authorization")
  if (!token) return res.status(401).json({ error: "Access denied" })
  try {
    const jwt = require("jsonwebtoken")

    function verifyToken(req, res, next) {
      // Retrieve the token from cookies
      const token = req.cookies.authToken
      if (!token) {
        return res
          .status(401)
          .json({ error: "Access denied. No token provided." })
      }

      try {
        // Verify the token
        const decoded = jwt.verify(token, "qur3ur83ut8u8")
        req.userId = decoded.userId // Store the userId for later use
        next() // Proceed to the next middleware
      } catch (error) {
        res.status(401).json({ error: "Invalid token." })
      }
    }

    module.exports = verifyToken
    decoded = jwt.verify(token, "qur3ur83ut8u8")
    req.userId = decoded.userId
    next()
  } catch (error) {
    res.status(401).json({ error: "Invalid token" })
  }
}

module.exports = verifyToken
