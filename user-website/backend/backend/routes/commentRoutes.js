const express = require("express")
const Comment = require("../models/Comment")
const verifyToken = require("../middleware/Authenticate")
const router = express.Router()

router.post("/add", verifyToken, async (req, res) => {
  const { blogId, comment } = req.body

  if (!blogId || !comment) {
    return res.status(400).json({ error: "Blog ID and comment are required" })
  }

  const username = req.user.username
  try {
    const newComment = new Comment({
      blogId,
      username,
      comment,
    })
    await newComment.save()
    res
      .status(200)
      .send({ success: true, message: "Comment added successfully!" })
  } catch (err) {
    console.error("Failed to add comment:", err)
    res.status(500).send({ error: "Failed to add comment" })
  }
})

router.get("/:blogId", async (req, res) => {
  const blogId = req.params.blogId
  try {
    const comments = await Comment.find({ blogId }).sort({ createdAt: -1 })
    res.status(200).json(comments)
  } catch (err) {
    res.status(500).send({ error: "Failed to fetch comments" })
  }
})

module.exports = router
