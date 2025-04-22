const blogContainer = document.getElementById("blog-container")
const modal = document.getElementById("modal")
const modalTitle = document.getElementById("modal-title")
const modalDescription = document.getElementById("modal-description")
const searchBar = document.getElementById("search-bar")
const searchButton = document.querySelector(".search-btn")

let isLoggedIn = false
let currentUsername = ""
let blogs = []

// Check logged-in user
async function fetchUser() {
  try {
    const res = await fetch("/auth/current-user")
    const data = await res.json()
    if (data.username) {
      isLoggedIn = true
      currentUsername = data.username
    }
  } catch (err) {
    console.error("User check failed:", err)
  }
}

// Fetch blogs from backend
async function fetchBlogs() {
  try {
    const res = await fetch("/blogs")
    blogs = await res.json()
    renderBlogs(blogs)
  } catch (err) {
    console.error("Failed to fetch blogs:", err)
  }
}

// Render blogs
function renderBlogs(filteredBlogs = blogs) {
  blogContainer.innerHTML = ""
  filteredBlogs.forEach((blog) => {
    const card = document.createElement("div")
    card.className = "blog-card"

    const deleteButton = `
  <button class="delete-btn" onclick="event.stopPropagation(); confirmDelete(${blog.id})">Delete</button>
`

    card.innerHTML = `
      ${deleteButton}
      <img src="${blog.image}" alt="Blog Image" />
      <div class="content">
        <h3>${blog.title}</h3>
        <p>${blog.description}</p>
      </div>
    `
    card.onclick = () => showBlogDetails(blog.id)
    blogContainer.appendChild(card)
  })
}

function confirmDelete(blogId) {
  if (confirm("Delete this blog?")) {
    fetch(`/delete/${blogId}`, {
      method: "DELETE",
    })
      .then((response) => {
        if (response.ok) {
          alert("Blog deleted successfully!")
          renderBlogs(blogs.filter((blog) => blog.id !== blogId))
        } else {
          alert("Failed to delete blog!")
        }
      })
      .catch((error) => {
        console.error("Error deleting blog:", error)
        alert("An error occurred while deleting the blog.")
      })
  }
}

function filterBlogs() {
  const query = searchBar.value.toLowerCase()
  const filtered = blogs.filter(
    (blog) =>
      blog.title.toLowerCase().includes(query) ||
      blog.description.toLowerCase().includes(query)
  )
  renderBlogs(filtered)
}

function showBlogDetails(id) {
  const blog = blogs.find((b) => b.id === id)
  modalTitle.textContent = blog.title
  modalDescription.textContent = blog.details
  modal.style.display = "flex"
}
function closeModal() {
  modal.style.display = "none"
}

searchButton.addEventListener("click", filterBlogs)
searchBar.addEventListener("keyup", (e) => e.key === "Enter" && filterBlogs())

fetchUser().then(fetchBlogs)
