const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const router = express.Router();
const { authenticateToken, JWT_SECRET } = require("./middleware");

// ─── User Schema ──────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  passwordHash: { type: String, required: true },
  role: {
    type: String,
    enum: ["admin", "analyst", "viewer"],
    default: "viewer",
  },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  loginAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date },
  createdAt: { type: Date, default: Date.now },
  refreshTokens: [{ type: String }], // Store hashed refresh tokens
});

const User = mongoose.models.User || mongoose.model("User", userSchema);

// ─── Refresh Token Schema ─────────────────────────────────────────────────────
const refreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  tokenHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

const RefreshToken =
  mongoose.models.RefreshToken ||
  mongoose.model("RefreshToken", refreshTokenSchema);

// ─── Helpers ──────────────────────────────────────────────────────────────────
const SALT_ROUNDS = 12;
const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

function generateAccessToken(user) {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY },
  );
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user._id }, JWT_SECRET + "_refresh", {
    expiresIn: REFRESH_TOKEN_EXPIRY,
  });
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
  // Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/.test(
    password,
  );
}

// ─── REGISTER ─────────────────────────────────────────────────────────────────
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email, and password are required." });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid email format." });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
      });
    }

    // Check for existing user
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({
        error:
          existing.email === email.toLowerCase()
            ? "Email already registered."
            : "Username already taken.",
      });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // First user becomes admin automatically
    const userCount = await User.countDocuments();
    const assignedRole = userCount === 0 ? "admin" : role || "viewer";

    const user = new User({
      username,
      email,
      passwordHash,
      role: assignedRole,
    });
    await user.save();

    // Log the registration
    console.log(`[AUTH] New user registered: ${username} (${assignedRole})`);

    res.status(201).json({
      message: "Account created successfully.",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("[AUTH] Register error:", err);
    res.status(500).json({ error: "Server error during registration." });
  }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
router.post("/login", async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier = email or username

    if (!identifier || !password) {
      return res.status(400).json({ error: "Credentials are required." });
    }

    const user = await User.findOne({
      $or: [{ email: identifier.toLowerCase() }, { username: identifier }],
    });

    // Account not found - generic message for security
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    // Check if account is active
    if (!user.isActive) {
      return res
        .status(403)
        .json({ error: "Account is disabled. Contact an administrator." });
    }

    // Check lockout
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const remainingMs = user.lockedUntil - new Date();
      const remainingMin = Math.ceil(remainingMs / 60000);
      return res.status(429).json({
        error: `Account temporarily locked. Try again in ${remainingMin} minute(s).`,
      });
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
        user.loginAttempts = 0;
        await user.save();
        return res.status(429).json({
          error: "Too many failed attempts. Account locked for 15 minutes.",
        });
      }

      await user.save();
      const attemptsLeft = MAX_LOGIN_ATTEMPTS - user.loginAttempts;
      return res.status(401).json({
        error: `Invalid credentials. ${attemptsLeft} attempt(s) remaining.`,
      });
    }
    user.loginAttempts = 0;
    user.lockedUntil = null;
    user.lastLogin = new Date();

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const tokenHash = await bcrypt.hash(refreshToken, 8);
    await RefreshToken.create({
      userId: user._id,
      tokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    await user.save();

    // Set httpOnly cookie for refresh token
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    console.log(`[AUTH] Login success: ${user.username} (${user.role})`);
    res.cookie("token", accessToken, {
      httpOnly: true,
      secure: false, // true in production (HTTPS)
      sameSite: "lax",
      maxAge: 15 * 60 * 1000, // 15 min
    });
    res.json({
      accessToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin,
      },
    });
  } catch (err) {
    console.error("[AUTH] Login error:", err);
    res.status(500).json({ error: "Server error during login." });
  }
});

// ─── REFRESH TOKEN ────────────────────────────────────────────────────────────
router.post("/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ error: "No refresh token provided." });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, JWT_SECRET + "_refresh");
    } catch {
      return res
        .status(403)
        .json({ error: "Invalid or expired refresh token." });
    }

    // Find matching stored token
    const stored = await RefreshToken.find({
      userId: decoded.id,
      expiresAt: { $gt: new Date() },
    });

    let validToken = null;
    for (const t of stored) {
      if (await bcrypt.compare(refreshToken, t.tokenHash)) {
        validToken = t;
        break;
      }
    }

    if (!validToken) {
      return res
        .status(403)
        .json({ error: "Refresh token revoked or not found." });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) {
      return res.status(403).json({ error: "User not found or disabled." });
    }

    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error("[AUTH] Refresh error:", err);
    res.status(500).json({ error: "Server error during token refresh." });
  }
});

// ─── LOGOUT ───────────────────────────────────────────────────────────────────
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      // Revoke the specific refresh token
      const stored = await RefreshToken.find({ userId: req.user.id });
      for (const t of stored) {
        if (await bcrypt.compare(refreshToken, t.tokenHash)) {
          await RefreshToken.deleteOne({ _id: t._id });
          break;
        }
      }
    }

    res.clearCookie("refreshToken");
    console.log(`[AUTH] Logout: ${req.user.username}`);
    res.json({ message: "Logged out successfully." });
  } catch (err) {
    console.error("[AUTH] Logout error:", err);
    res.status(500).json({ error: "Server error during logout." });
  }
});

// ─── PROFILE ──────────────────────────────────────────────────────────────────
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-passwordHash -refreshTokens",
    );
    if (!user) return res.status(404).json({ error: "User not found." });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
router.put("/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Both passwords are required." });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        error: "New password does not meet strength requirements.",
      });
    }

    const user = await User.findById(req.user.id);
    const isValid = await bcrypt.compare(currentPassword, user.passwordHash);

    if (!isValid) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }

    user.passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await user.save();

    // Revoke all refresh tokens (force re-login on all devices)
    await RefreshToken.deleteMany({ userId: user._id });
    res.clearCookie("refreshToken");

    res.json({
      message: "Password changed successfully. Please log in again.",
    });
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

// ─── LIST USERS (admin only) ──────────────────────────────────────────────────
router.get("/users", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required." });
    }

    const users = await User.find()
      .select("-passwordHash -refreshTokens")
      .sort({ createdAt: -1 });
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

// ─── UPDATE USER ROLE (admin only) ────────────────────────────────────────────
router.put("/users/:id/role", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required." });
    }

    const { role } = req.body;
    if (!["admin", "analyst", "viewer"].includes(role)) {
      return res.status(400).json({ error: "Invalid role." });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true },
    ).select("-passwordHash");

    if (!user) return res.status(404).json({ error: "User not found." });

    res.json({ message: "Role updated.", user });
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

module.exports = { router, User };
