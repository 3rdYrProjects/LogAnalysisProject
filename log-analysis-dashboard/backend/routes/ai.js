const express = require("express");
const router = express.Router();

require("dotenv").config();

router.post("/", async (req, res) => {
  const { prompt } = req.body;

  if (!prompt) {
    return res.status(400).json({ response: "Prompt is required" });
  }

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=AIzaSyAIG2rAEiPrdC9JVrm4xw2vN57g25s2bh8`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            {
              role: "user",
              parts: [{ text: prompt }],
            },
          ],
        }),
      }
    );

    const result = await response.json();

    // Safely extract the text
    const output =
      result?.candidates?.[0]?.content?.parts?.[0]?.text ||
      result?.promptFeedback?.blockReason ||
      "No response received";

    res.json({ response: output });
  } catch (err) {
    console.error("Gemini API Error:", err);
    res.status(500).json({ response: "AI service unavailable" });
  }
});

module.exports = router;
