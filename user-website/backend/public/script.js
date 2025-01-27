const blogs = [
  {
    id: 1,
    title: "Understanding SQL Injection",
    description:
      "An introduction to SQL injection techniques and prevention methods.",
    image:
      "https://cybersapiens.com.au/wp-content/uploads/2024/06/list-of-100-plus-best-cyber-security-blogs-in-the-world-1024x536.jpg",
    details:
      "SQL injection is a type of security vulnerability where an attacker can execute arbitrary SQL code on the database by injecting malicious input.",
  },
  {
    id: 2,
    title: "Cross-Site Scripting (XSS) Guide",
    description:
      "Learn how XSS attacks work and how to secure your applications.",
    image:
      "https://erepublic.brightspotcdn.com/dims4/default/bcd15e7/2147483647/strip/true/crop/940x490+0+68/resize/840x438!/quality/90/?url=http%3A%2F%2Ferepublic-brightspot.s3.us-west-2.amazonaws.com%2Fc7%2Fe6%2F15cc0c2a576e7e7b79495dba3677%2Fshutterstock-281522084.jpg",
    details:
      "XSS allows attackers to inject malicious scripts into webpages viewed by other users. This guide explains how to protect against such attacks.",
  },
  {
    id: 3,
    title: "Top 10 OWASP Vulnerabilities",
    description:
      "A detailed guide on OWASP's top vulnerabilities for web applications.",
    image:
      "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSU1awa_S5x958hmS1sST4ZubzyaRNIi9Tksg&s",
    details:
      "OWASP Top 10 is a standard awareness document for developers and security professionals. Learn how to mitigate these vulnerabilities.",
  },
]

const blogContainer = document.getElementById("blog-container")
const modal = document.getElementById("modal")
const modalTitle = document.getElementById("modal-title")
const modalDescription = document.getElementById("modal-description")
const commentInput = document.getElementById("comment-input")
const commentsData = {} // Object to store comments for each blog

function renderBlogs() {
  blogs.forEach((blog) => {
    const card = document.createElement("div")
    card.className = "blog-card"
    card.innerHTML = `
        <img src="${blog.image}" alt="Blog Image">
        <div class="content">
          <h3>${blog.title}</h3>
          <p>${blog.description}</p>
        </div>
      `
    card.onclick = () => showBlogDetails(blog.id)
    blogContainer.appendChild(card)
  })
}

function showBlogDetails(id) {
  const blog = blogs.find((b) => b.id === id)
  modalTitle.textContent = blog.title
  modalDescription.textContent = blog.details
  modal.dataset.blogId = id // Store the current blog ID in the modal
  modal.style.display = "flex"

  // Clear and display comments for the selected blog
  const commentSection = document.querySelector(".comments")
  const existingComments = commentSection.querySelectorAll(".comment")
  existingComments.forEach((comment) => comment.remove())

  if (commentsData[id]) {
    commentsData[id].forEach((commentText) => {
      const newComment = document.createElement("div")
      newComment.className = "comment"
      newComment.textContent = commentText
      commentSection.insertBefore(
        newComment,
        commentSection.querySelector(".add-comment")
      )
    })
  }
}

function closeModal() {
  modal.style.display = "none"
}

function addComment() {
  const commentText = commentInput.value.trim()
  if (commentText) {
    const blogId = modal.dataset.blogId
    if (!commentsData[blogId]) {
      commentsData[blogId] = []
    }
    commentsData[blogId].push(commentText)

    const commentSection = document.querySelector(".comments")
    const newComment = document.createElement("div")
    newComment.className = "comment"
    newComment.textContent = commentText
    commentSection.insertBefore(
      newComment,
      commentSection.querySelector(".add-comment")
    )

    commentInput.value = ""
  }
}

// Add event listener to submit comment on pressing "Enter"
commentInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    addComment()
  }
})

renderBlogs()
