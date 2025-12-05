async function callGemini(prompt) {
  try {
    const res = await fetch("http://localhost:4000/api/ai", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    });

    const data = await res.json();
    return data.response || "No AI response generated.";
  } catch (err) {
    console.error("AI Error:", err);
    return "AI summarization unavailable.";
  }
}
