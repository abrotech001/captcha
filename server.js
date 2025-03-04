// Enhanced captcha server implementation (CommonJS)
const express = require("express")
const session = require("express-session")
const crypto = require("crypto")
const path = require("path")
const fs = require("fs")
const app = express()

// Generate a secure session secret if not provided
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex")

// Configure session middleware with enhanced security
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 15 * 60 * 1000, // 15 minutes (shorter for security)
      httpOnly: true,
      sameSite: "strict",
    },
  }),
)

// Middleware and body parser setup
app.use(express.static(path.join(__dirname, "public")))
app.use(express.urlencoded({ extended: false }))

// Security headers middleware
app.use((req, res, next) => {
  // Basic security headers
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("X-XSS-Protection", "1; mode=block")
  next()
})

// Rate limiting middleware (simple implementation)
const ipRequests = new Map()
const MAX_REQUESTS = 50 // Max requests per IP
const WINDOW_MS = 10 * 60 * 1000 // 10 minutes

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress

  if (!ipRequests.has(ip)) {
    ipRequests.set(ip, {
      count: 1,
      resetAt: Date.now() + WINDOW_MS,
    })
  } else {
    const data = ipRequests.get(ip)

    // Reset counter if time window has passed
    if (Date.now() > data.resetAt) {
      data.count = 1
      data.resetAt = Date.now() + WINDOW_MS
    } else if (data.count >= MAX_REQUESTS) {
      return res.status(429).send("Too many requests. Please try again later.")
    } else {
      data.count++
    }
  }

  next()
})

// Clean up expired rate limit entries every hour
setInterval(
  () => {
    const now = Date.now()
    for (const [ip, data] of ipRequests.entries()) {
      if (now > data.resetAt) {
        ipRequests.delete(ip)
      }
    }
  },
  60 * 60 * 1000,
)

// Create captcha-utils.js file if it doesn't exist
const captchaUtilsPath = path.join(__dirname, "captcha-utils.js")
if (!fs.existsSync(captchaUtilsPath)) {
  const captchaUtilsContent = `
// Enhanced captcha utilities (CommonJS)
const crypto = require('crypto');

/**
 * Generates a captcha challenge
 * @returns {Object} Object containing the captcha display text and answer
 */
function generateCaptcha() {
  // Define character sets for captcha (excluding similar looking characters)
  const letters = 'abcdefghjkmnpqrstuvwxyz';
  const numbers = '23456789';
  const allChars = letters + letters.toUpperCase() + numbers;
  
  // Generate a random captcha of 5-7 characters
  const length = Math.floor(Math.random() * 3) + 5; // 5-7 characters
  let captchaText = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * allChars.length);
    captchaText += allChars[randomIndex];
  }
  
  // Apply some visual distortion
  const displayText = captchaText.split('').map(char => {
    // Randomly apply some styling to each character
    const styles = [
      \`<span style="transform: rotate(\${Math.random() * 20 - 10}deg); display: inline-block;">\${char}</span>\`,
      \`<span style="font-size: \${Math.random() * 0.5 + 0.8}em;">\${char}</span>\`,
      \`<span style="margin-left: \${Math.random() * 5}px;">\${char}</span>\`,
      \`<span style="color: rgb(\${Math.floor(Math.random() * 100)}, \${Math.floor(Math.random() * 100)}, \${Math.floor(Math.random() * 100)});">\${char}</span>\`
    ];
    return styles[Math.floor(Math.random() * styles.length)];
  }).join('');
  
  // Generate a hash of the answer for additional security
  const hash = crypto.createHash('sha256').update(captchaText.toLowerCase()).digest('hex');
  
  return {
    display: displayText,
    answer: captchaText,
    hash: hash
  };
}

/**
 * Validates user input against the captcha answer
 * @param {string} userInput - The user's input
 * @param {string} answer - The correct captcha answer
 * @param {Object} options - Validation options
 * @param {boolean} options.caseSensitive - Whether validation should be case sensitive
 * @returns {boolean} Whether the input is valid
 */
function validate(userInput, answer, options = { caseSensitive: true }) {
  if (!userInput || !answer) return false;
  
  if (options.caseSensitive) {
    return userInput === answer;
  } else {
    return userInput.toLowerCase() === answer.toLowerCase();
  }
}

/**
 * Validates user input against a hash of the answer
 * @param {string} userInput - The user's input
 * @param {string} hash - The hash of the correct answer
 * @returns {boolean} Whether the input is valid
 */
function validateWithHash(userInput, hash) {
  if (!userInput || !hash) return false;
  
  const inputHash = crypto.createHash('sha256').update(userInput.toLowerCase()).digest('hex');
  return inputHash === hash;
}

module.exports = { generateCaptcha, validate, validateWithHash };
  `
  fs.writeFileSync(captchaUtilsPath, captchaUtilsContent)
  console.log("Created enhanced captcha-utils.js")
}

// Import captcha utilities
const { generateCaptcha, validateWithHash } = require("./captcha-utils")

// Middleware to check if user has passed captcha
const captchaMiddleware = (req, res, next) => {
  // Check if session exists and is valid
  if (!req.session) {
    return res.status(500).send("Session error. Please try again.")
  }

  // Check if captcha is passed and not expired
  if (req.session.captchaPassed && req.session.captchaPassedAt) {
    const captchaAge = Date.now() - req.session.captchaPassedAt
    const maxCaptchaAge = 60 * 60 * 1000 // 1 hour

    if (captchaAge < maxCaptchaAge) {
      // Captcha is still valid
      return next()
    }
    // Captcha expired, clear the session data
    delete req.session.captchaPassed
    delete req.session.captchaPassedAt
  }

  // Redirect to captcha page
  res.redirect("/captcha")
}

// Captcha page route
app.get("/captcha", (req, res) => {
  // Generate a new captcha for this session
  const captcha = generateCaptcha()

  // Store only the hash in the session for security
  req.session.captchaHash = captcha.hash

  // Add a timestamp to track when this captcha was generated
  req.session.captchaGeneratedAt = Date.now()

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify - Abrotech</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background-color: #f5f5f5;
        }
        .captcha-container {
          background: white;
          padding: 2rem;
          border-radius: 8px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          text-align: center;
          max-width: 400px;
          width: 100%;
        }
        .captcha-image {
          background: #e0e0e0;
          padding: 1rem;
          margin: 1rem 0;
          border-radius: 4px;
          font-size: 1.5rem;
          letter-spacing: 2px;
          font-weight: bold;
          user-select: none;
        }
        input {
          width: 100%;
          padding: 0.75rem;
          margin: 0.5rem 0;
          border: 1px solid #ddd;
          border-radius: 4px;
          box-sizing: border-box;
        }
        button {
          background: #4CAF50;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 4px;
          cursor: pointer;
          font-size: 1rem;
          margin-top: 1rem;
        }
        button:hover {
          background: #45a049;
        }
        .error {
          color: red;
          margin-top: 0.5rem;
        }
        .refresh {
          color: #0066cc;
          text-decoration: none;
          margin-top: 1rem;
          display: inline-block;
          font-size: 0.9rem;
        }
        .refresh:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="captcha-container">
        <h2>Verification Required</h2>
        <p>Please enter the text below to continue to Abrotech</p>
        <div class="captcha-image">${captcha.display}</div>
        <form action="/verify-captcha" method="POST">
          <input type="text" name="captchaInput" placeholder="Enter the text above" required autocomplete="off">
          <button type="submit">Verify</button>
          ${req.session.captchaError ? `<p class="error">${req.session.captchaError}</p>` : ""}
        </form>
        <a href="/captcha" class="refresh">Get a new captcha</a>
      </div>
    </body>
    </html>
  `)

  // Clear any previous error message
  req.session.captchaError = null
})

// Verify captcha submission
app.post("/verify-captcha", (req, res) => {
  const userInput = req.body.captchaInput
  const hash = req.session.captchaHash
  const generatedAt = req.session.captchaGeneratedAt || 0

  // Check if captcha has expired (2 minutes max)
  const captchaAge = Date.now() - generatedAt
  const maxCaptchaAge = 2 * 60 * 1000 // 2 minutes

  if (captchaAge > maxCaptchaAge) {
    req.session.captchaError = "Captcha expired. Please try again."
    return res.redirect("/captcha")
  }

  if (validateWithHash(userInput, hash)) {
    // Captcha passed
    req.session.captchaPassed = true
    req.session.captchaPassedAt = Date.now()

    // Clear captcha data
    delete req.session.captchaHash
    delete req.session.captchaGeneratedAt

    res.redirect("/") // Redirect to main page
  } else {
    // Captcha failed
    req.session.captchaError = "Incorrect captcha. Please try again."
    res.redirect("/captcha")
  }
})

// Apply captcha middleware to protect routes
app.use(/^\/(?!captcha|verify-captcha|favicon.ico|robots.txt).*$/, captchaMiddleware)

// Main page route (protected by captcha)
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Abrotech</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          padding: 2rem;
          max-width: 800px;
          margin: 0 auto;
        }
        h1 {
          color: #333;
        }
      </style>
    </head>
    <body>
      <h1>Welcome to Abrotech!</h1>
      <p>You have successfully passed the captcha verification.</p>
      <!-- Your main website content goes here -->
    </body>
    </html>
  `)
})

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).send("Something broke! Please try again later.")
})

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully")
  process.exit(0)
})

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully")
  process.exit(0)
})

// Start the server
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Enhanced captcha server running on port ${PORT}`)
})

