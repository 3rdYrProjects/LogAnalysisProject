const jwt = require("jsonwebtoken");
const JWT_SECRET =
  process.env.JWT_SECRET || "cyberlog_secret_2024_change_in_prod";

/**
 * Middleware to verify JWT token from Authorization header or cookie
 */
function authenticateToken(req, res, next) {
  // Support both Bearer token and cookie-based auth
  const authHeader = req.headers["authorization"];
  const token =
    (authHeader && authHeader.startsWith("Bearer ") && authHeader.slice(7)) ||
    req.cookies?.token;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token." });
  }
}

/**
 * Role-based access control middleware
 * @param {...string} roles - Allowed roles
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Required role: ${roles.join(" or ")}`,
      });
    }
    next();
  };
}

module.exports = { authenticateToken, requireRole, JWT_SECRET };
