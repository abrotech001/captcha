// Enhanced captcha server implementation for main domain integration
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

// Define captcha utilities directly in the server.js file
const captchaUtils = {
  /**
   * Generates a captcha challenge
   * @returns {Object} Object containing the captcha display text and answer
   */
  generateCaptcha: () => {
    // Define character sets for captcha (excluding similar looking characters)
    const letters = "abcdefghjkmnpqrstuvwxyz"
    const numbers = "23456789"
    const allChars = letters + letters.toUpperCase() + numbers

    // Generate a random captcha of 5-7 characters
    const length = Math.floor(Math.random() * 3) + 5 // 5-7 characters
    let captchaText = ""

    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * allChars.length)
      captchaText += allChars[randomIndex]
    }

    // Apply some visual distortion
    const displayText = captchaText
      .split("")
      .map((char) => {
        // Randomly apply some styling to each character
        const styles = [
          `<span style="transform: rotate(${Math.random() * 20 - 10}deg); display: inline-block;">${char}</span>`,
          `<span style="font-size: ${Math.random() * 0.5 + 0.8}em;">${char}</span>`,
          `<span style="margin-left: ${Math.random() * 5}px;">${char}</span>`,
          `<span style="color: rgb(${Math.floor(Math.random() * 100)}, ${Math.floor(Math.random() * 100)}, ${Math.floor(Math.random() * 100)});">${char}</span>`,
        ]
        return styles[Math.floor(Math.random() * styles.length)]
      })
      .join("")

    // Generate a hash of the answer for additional security
    const hash = crypto.createHash("sha256").update(captchaText.toLowerCase()).digest("hex")

    return {
      display: displayText,
      answer: captchaText,
      hash: hash,
    }
  },

  /**
   * Validates user input against a hash of the answer
   * @param {string} userInput - The user's input
   * @param {string} hash - The hash of the correct answer
   * @returns {boolean} Whether the input is valid
   */
  validateWithHash: (userInput, hash) => {
    if (!userInput || !hash) return false

    const inputHash = crypto.createHash("sha256").update(userInput.toLowerCase()).digest("hex")
    return inputHash === hash
  },
}

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

  // Redirect to captcha verification
  res.redirect("/verify")
}

// Prevent access to /verify if already verified
const preventVerifyAccessIfVerified = (req, res, next) => {
  // Check if session exists
  if (!req.session) {
    return next()
  }

  // Check if user has passed captcha and it's still valid
  if (req.session.captchaPassed && req.session.captchaPassedAt) {
    const captchaAge = Date.now() - req.session.captchaPassedAt
    const maxCaptchaAge = 60 * 60 * 1000 // 1 hour

    if (captchaAge < maxCaptchaAge) {
      console.log("User already verified, redirecting from /verify to homepage")
      // Already verified, redirect to main page
      return res.redirect("/")
    }
  }

  // Not verified or verification expired, proceed to captcha page
  next()
}

// Captcha verification page
app.get("/verify", preventVerifyAccessIfVerified, (req, res) => {
  // Generate a new captcha for this session
  const captcha = captchaUtils.generateCaptcha()
  
  console.log("Generated new captcha:", {
    answer: captcha.answer, // Log the answer for debugging
    hash: captcha.hash
  });

  // Store only the hash in the session for security
  req.session.captchaHash = captcha.hash

  // Add a timestamp to track when this captcha was generated
  req.session.captchaGeneratedAt = Date.now()

  // Make sure to include the form with proper enctype
  // This is a critical part that needs to be in your HTML
  /*
  <form action="/process-verify" method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="captchaInput" placeholder="Enter the text above" required autocomplete="off">
    <button type="submit">Verify</button>
    ${req.session.captchaError ? `<p class="error">${req.session.captchaError}</p>` : ""}
  </form>
  */

  // Clear any previous error message
  req.session.captchaError = null
})

// Fix for the regex pattern in the middleware
// The original regex might be missing some paths that should be excluded
app.use(/^\/(?!verify|process-verify|favicon\.ico|robots\.txt).*$/, captchaMiddleware)

// Add a test route to check if the captcha system is working
app.get("/test-captcha", (req, res) => {
  const captcha = captchaUtils.generateCaptcha();
  const testInput = captcha.answer;
  const isValid = captchaUtils.validateWithHash(testInput, captcha.hash);
  
  res.send(`
    <h1>Captcha Test</h1>
    <p>Generated captcha: ${captcha.answer}</p>
    <p>Hash: ${captcha.hash}</p>
    <p>Test validation (should be true): ${isValid}</p>
    <p>Test validation with wrong input (should be false): ${captchaUtils.validateWithHash("wrong", captcha.hash)}</p>
  `);
});
  

// Process captcha verification
app.post("/process-verify", (req, res) => {
  console.log("POST request received at /process-verify");
  console.log("Request body:", req.body);
  console.log("Session data:", {
    hash: req.session.captchaHash,
    generatedAt: req.session.captchaGeneratedAt,
    error: req.session.captchaError
  });
  
  const userInput = req.body.captchaInput
  const hash = req.session.captchaHash
  const generatedAt = req.session.captchaGeneratedAt || 0

  // Check if captcha has expired (2 minutes max)
  const captchaAge = Date.now() - generatedAt
  const maxCaptchaAge = 2 * 60 * 1000 // 2 minutes

  console.log("Captcha age:", captchaAge, "ms (max:", maxCaptchaAge, "ms)");
  
  if (captchaAge > maxCaptchaAge) {
    console.log("Captcha expired");
    req.session.captchaError = "Captcha expired. Please try again."
    return res.redirect("/verify")
  }

  // Debug validation
  console.log("User input:", userInput);
  if (!userInput) {
    console.log("No user input provided");
    req.session.captchaError = "Please enter the captcha text."
    return res.redirect("/verify")
  }
  
  if (!hash) {
    console.log("No hash found in session");
    req.session.captchaError = "Session error. Please try again."
    return res.redirect("/verify")
  }

  // Test validation
  const inputHash = crypto.createHash("sha256").update(userInput.toLowerCase()).digest("hex");
  console.log("Input hash:", inputHash);
  console.log("Stored hash:", hash);
  console.log("Hashes match:", inputHash === hash);

  if (captchaUtils.validateWithHash(userInput, hash)) {
    console.log("Captcha validation passed");
    // Captcha passed
    req.session.captchaPassed = true
    req.session.captchaPassedAt = Date.now()

    // Clear captcha data
    delete req.session.captchaHash
    delete req.session.captchaGeneratedAt

    // Store the original URL if it exists, otherwise go to home
    const redirectTo = req.session.originalUrl || "/"
    delete req.session.originalUrl

    console.log("Redirecting to:", redirectTo);
    return res.redirect(redirectTo)
  } else {
    console.log("Captcha validation failed");
    // Captcha failed
    req.session.captchaError = "Incorrect captcha. Please try again."
    return res.redirect("/verify")
  }
})

// Default route handler for the root URL
app.get("/", (req, res) => {
  // Check if index.html exists in the public directory
  const indexPath = path.join(__dirname, "view", "index.html")

  if (fs.existsSync(indexPath)) {
    // If index.html exists, serve it
    res.sendFile(indexPath)
  } else {
    // Otherwise, show a default page
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
        <p>To display your website content, place your HTML files in the "public" directory.</p>
      </body>
      </html>
    `)
  }
})

// Test route to check verification status
app.get("/verification-status", (req, res) => {
  const isVerified = req.session.captchaPassed && req.session.captchaPassedAt
  const verifiedTime = req.session.captchaPassedAt
    ? new Date(req.session.captchaPassedAt).toLocaleString()
    : "Not verified"
  const timeRemaining = isVerified
    ? Math.floor((req.session.captchaPassedAt + 60 * 60 * 1000 - Date.now()) / 1000 / 60) + " minutes"
    : "Not applicable"

  res.send(`
    <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verification Status</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600&display=swap');

    :root {
      --primary: #4CAF50;
      --primary-dark: #3d8b40;
      --bg-dark: #121212;
      --card-bg: #1e1e1e;
      --card-bg-hover: #252525;
      --text-light: #f5f5f5;
      --text-muted: #b0b0b0;
      --success-bg: #1e3a1e;
      --success-border: #2a5a2a;
      --success-text: #4CAF50;
      --error-bg: #3a1e1e;
      --error-border: #5a2a2a;
      --error-text: #ff5252;
      --code-bg: #2a2a2a;
      --link-color: #4CAF50;
      --link-hover: #3d8b40;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Poppins', sans-serif;
      min-height: 100vh;
      background: var(--bg-dark);
      color: var(--text-light);
      perspective: 1000px;
      overflow-x: hidden;
      background: radial-gradient(circle at center, #1a1a1a, #0a0a0a);
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem;
    }

    .container {
      max-width: 800px;
      width: 100%;
      transform-style: preserve-3d;
    }

    h1 {
      color: var(--primary);
      margin-bottom: 1.5rem;
      font-weight: 600;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
      transform: translateZ(20px);
      text-align: center;
    }

    h2 {
      color: var(--primary);
      margin: 2rem 0 1rem;
      font-weight: 500;
      font-size: 1.3rem;
      transform: translateZ(15px);
    }

    .status-card {
      background: var(--card-bg);
      padding: 2rem;
      border-radius: 16px;
      box-shadow: 
        0 10px 25px rgba(0, 0, 0, 0.4),
        0 6px 12px rgba(0, 0, 0, 0.2),
        0 0 0 1px rgba(255, 255, 255, 0.05) inset;
      transform-style: preserve-3d;
      transform: rotateX(5deg);
      transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      position: relative;
      z-index: 1;
      margin-bottom: 2rem;
    }

    .status-card:hover {
      transform: rotateX(0deg) translateY(-10px);
      box-shadow: 
        0 20px 40px rgba(0, 0, 0, 0.5),
        0 12px 24px rgba(0, 0, 0, 0.3),
        0 0 0 1px rgba(255, 255, 255, 0.07) inset;
    }

    .status {
      padding: 1.5rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
      transform: translateZ(30px);
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
      border: 1px solid transparent;
    }

    .status::before {
      content: '';
      position: absolute;
      top: -2px;
      left: -2px;
      right: -2px;
      bottom: -2px;
      z-index: -1;
      border-radius: 8px;
      opacity: 0.1;
      transition: opacity 0.4s ease;
    }

    .status:hover {
      transform: translateZ(35px);
    }

    .status:hover::before {
      opacity: 0.2;
    }

    .verified {
      background-color: var(--success-bg);
      border-color: var(--success-border);
      color: var(--success-text);
    }

    .verified::before {
      background: linear-gradient(45deg, var(--primary), transparent, var(--primary));
    }

    .not-verified {
      background-color: var(--error-bg);
      border-color: var(--error-border);
      color: var(--error-text);
    }

    .not-verified::before {
      background: linear-gradient(45deg, var(--error-text), transparent, var(--error-text));
    }

    .status p {
      margin-bottom: 0.5rem;
      font-size: 1rem;
      line-height: 1.6;
    }

    .status p:last-child {
      margin-bottom: 0;
    }

    .status strong {
      font-weight: 500;
      opacity: 0.9;
    }

    .info-text {
      color: var(--text-muted);
      margin-bottom: 1.5rem;
      line-height: 1.6;
      transform: translateZ(10px);
    }

    .links {
      display: flex;
      gap: 1rem;
      margin-bottom: 2rem;
      transform: translateZ(20px);
    }

    .link-button {
      display: inline-block;
      padding: 0.75rem 1.5rem;
      background: var(--card-bg-hover);
      color: var(--link-color);
      text-decoration: none;
      border-radius: 8px;
      font-weight: 500;
      transition: all 0.3s ease;
      border: 1px solid rgba(76, 175, 80, 0.2);
      box-shadow: 
        0 4px 8px rgba(0, 0, 0, 0.2),
        0 2px 4px rgba(0, 0, 0, 0.1);
      position: relative;
      overflow: hidden;
    }

    .link-button::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(
        90deg,
        transparent,
        rgba(255, 255, 255, 0.1),
        transparent
      );
      transition: all 0.6s ease;
    }

    .link-button:hover {
      background: var(--card-bg);
      color: var(--link-hover);
      transform: translateY(-3px);
      box-shadow: 
        0 6px 12px rgba(0, 0, 0, 0.3),
        0 3px 6px rgba(0, 0, 0, 0.2);
      border-color: rgba(76, 175, 80, 0.4);
    }

    .link-button:hover::before {
      left: 100%;
    }

    .link-button:active {
      transform: translateY(-1px);
      box-shadow: 
        0 2px 4px rgba(0, 0, 0, 0.2),
        0 1px 2px rgba(0, 0, 0, 0.1);
    }

    pre {
      background: var(--code-bg);
      padding: 1.5rem;
      border-radius: 8px;
      overflow-x: auto;
      color: var(--text-light);
      font-family: 'Consolas', monospace;
      font-size: 0.9rem;
      line-height: 1.5;
      transform: translateZ(10px);
      transition: all 0.3s ease;
      border: 1px solid rgba(255, 255, 255, 0.05);
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }

    pre:hover {
      transform: translateZ(15px);
      box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
      border-color: rgba(255, 255, 255, 0.1);
    }

    /* Animation for page load */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .status-card, .pre-container {
      animation: fadeIn 0.6s ease-out forwards;
    }

    .pre-container {
      width: 100%;
      animation-delay: 0.2s;
      opacity: 0;
      animation-fill-mode: forwards;
    }

    /* Responsive adjustments */
    @media (max-width: 768px) {
      .container {
        padding: 1rem;
      }
      
      .links {
        flex-direction: column;
        gap: 0.5rem;
      }
      
      .link-button {
        width: 100%;
        text-align: center;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Verification Status</h1>
    
    <div class="status-card">
      <div class="status ${isVerified ? 'verified' : 'not-verified'}">
        <p><strong>Status:</strong> ${isVerified ? 'Verified' : 'Not Verified'}</p>
        <p><strong>Verified at:</strong> ${verifiedTime}</p>
        <p><strong>Time remaining:</strong> ${timeRemaining}</p>
      </div>
      
      <p class="info-text">This is a test page to check your verification status. If you're verified, trying to access /verify should redirect you to the homepage.</p>
      
      <div class="links">
        <a href="/verify" class="link-button">Try accessing /verify</a>
        <a href="/" class="link-button">Go to homepage</a>
      </div>
    </div>
    
    <h2>Session Data (Debug):</h2>
    <div class="pre-container">
      <pre>${JSON.stringify(req.session, null, 2)}</pre>
    </div>
  </div>
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
  console.log(`Server running on port ${PORT}`)
  console.log(`Captcha verification is active at /verify`)
  console.log(`Static files will be served from the 'public' directory after verification`)
  console.log(`Verification status check available at /verification-status`)
})

