// Define the base API URL for the backend
const API_BASE = "http://localhost:4000" // Log Analysis API URL

document.getElementById("signupForm")?.addEventListener("submit", async (e) => {
  e.preventDefault()

  const username = document.getElementById("username").value
  const password = document.getElementById("password").value

  const response = await fetch("/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  })

  if (response.ok) {
    alert("Signup successful")

    const logResponse = await sendLog(
      "User Signup",
      `User ${username} signed up successfully.`
    )

    if (logResponse.ok) {
      console.log("Log entry for signup created successfully.")
    } else {
      console.error("Failed to create log entry for signup.")
    }
  } else {
    alert("Signup failed")
  }
})

// Login Form Submission
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault()

  const username = document.getElementById("username").value
  const password = document.getElementById("password").value

  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  })

  if (response.ok) {
    alert("Login successful")

    // Create log entry for login action
    const logResponse = await sendLog(
      "User Login",
      `User ${username} logged in successfully.`
    )

    if (logResponse.ok) {
      console.log("Log entry for login created successfully.")
    } else {
      console.error("Failed to create log entry for login.")
    }
  } else {
    alert("Login failed")
  }
})

// Utility function to send logs
async function sendLog(activity, details) {
  try {
    const token = getAuthToken() // Get the auth token from cookies
    const logResponse = await fetch(`${API_BASE}/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`, // Include token for authentication
      },
      body: JSON.stringify({
        activity,
        details,
      }),
    })
    return logResponse
  } catch (error) {
    console.error("Error sending log:", error)
    return { ok: false }
  }
}

// Function to get auth token from cookies
function getAuthToken() {
  const cookieString = document.cookie
  const token = cookieString
    .split("; ")
    .find((row) => row.startsWith("authToken="))
    ?.split("=")[1]
  return token
}

window.onload = function () {
  checkAuth() // Ensure the navbar is updated based on auth token status
}

// Check if user is authenticated
async function checkAuth() {
  const token = getAuthToken()

  const buttonsDiv = document.getElementById("navbar-buttons")

  if (token) {
    // User is logged in, show Logout button
    buttonsDiv.innerHTML = `<button onclick="logout()">Logout</button>`
  } else {
    // User is not logged in, show Login and Signup buttons
    buttonsDiv.innerHTML = `
      <a href="/auth/login">Login</a>
      <a href="/auth/signup">Signup</a>
    `
  }
}

// Logout function to clear the token and update the navbar
async function logout() {
  try {
    const response = await fetch("/auth/logout", {
      method: "POST",
      credentials: "same-origin", // Ensure cookies are sent along with the request
    })

    if (response.ok) {
      alert("Logged out successfully.")
      checkAuth() // Update navbar after logout
      window.location.reload() // Reload the page to ensure everything is updated
    } else {
      alert("Failed to log out.")
    }
  } catch (error) {
    console.error("Logout error:", error)
  }
}
