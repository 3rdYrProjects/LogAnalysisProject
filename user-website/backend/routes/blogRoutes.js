const express = require("express")
const Comment = require("../models/Comment")
const router = express.Router()

// POST Comment Logic
router.post("/comment", async (req, res) => {
  try {
    const { blogId, username, comment } = req.body

    if (!blogId || !username || !comment) {
      return res.status(400).json({ error: "All fields are required" })
    }
    const newComment = await Comment.create({ blogId, username, comment })
    res
      .status(201)
      .json({ message: "Comment added successfully", comment: newComment })
  } catch (error) {
    console.error("Error saving comment:", error)
    res.status(500).json({ error: "Error saving comment" })
  }
})

// GET Comments for a Blog
router.get("/comments/:blogId", async (req, res) => {
  try {
    const { blogId } = req.params
    const comments = await Comment.find({ blogId }).sort({ createdAt: -1 }) // Fetch comments by blogId
    res.status(200).json({ comments })
  } catch (error) {
    console.error("Error fetching comments:", error)
    res.status(500).json({ error: "Error fetching comments" })
  }
})

module.exports = router
