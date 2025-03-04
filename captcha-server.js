// Import required modules
import express from 'express';
import session from 'express-session';
import { generateCaptcha, validate } from './captcha-utils.js';
import path from 'path';
import { fileURLToPath } from 'url';

// Convert ESM __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create Express app
const app = express();

// Configure session middleware
app.use(session({
  secret: 'your-secret-key', // Change this to a secure random string
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    maxAge: 30 * 60 * 1000 // Session expires after 30 minutes of inactivity
  }
}));

// Serve static files
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Middleware to check if user has passed captcha
const captchaMiddleware = (req, res, next) => {
  if (req.session.captchaPassed) {
    // If captcha is already passed, proceed to the next middleware
    next();
  } else {
    // Otherwise, redirect to captcha page
    res.redirect('/captcha');
  }
};

// Captcha page route
app.get('/captcha', (req, res) => {
  // Generate a new captcha for this session
  const captcha = generateCaptcha();
  req.session.captchaAnswer = captcha.answer;
  
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
      </style>
    </head>
    <body>
      <div class="captcha-container">
        <h2>Verification Required</h2>
        <p>Please enter the text below to continue to Abrotech</p>
        <div class="captcha-image">${captcha.display}</div>
        <form action="/verify-captcha" method="POST">
          <input type="text" name="captchaInput" placeholder="Enter the text above" required>
          <button type="submit">Verify</button>
          ${req.session.captchaError ? `<p class="error">${req.session.captchaError}</p>` : ''}
        </form>
      </div>
    </body>
    </html>
  `);
  
  // Clear any previous error message
  req.session.captchaError = null;
});

// Verify captcha submission
app.post('/verify-captcha', (req, res) => {
  const userInput = req.body.captchaInput;
  const answer = req.session.captchaAnswer;
  
  if (validate(userInput, answer, { caseSensitive: false })) {
    // Captcha passed
    req.session.captchaPassed = true;
    res.redirect('/'); // Redirect to main page
  } else {
    // Captcha failed
    req.session.captchaError = 'Incorrect captcha. Please try again.';
    res.redirect('/captcha');
  }
});

// Apply captcha middleware to all routes except the captcha routes
app.use(/^\/(?!captcha|verify-captcha).*$/, captchaMiddleware);

// Main page route (protected by captcha)
app.get('/', (req, res) => {
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
  `);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// For demonstration purposes only - this would normally be in a separate file
console.log('Server code created successfully. In a real implementation, you would:');
console.log('1. Save this to your project');
console.log('2. Create the captcha-utils.js file (shown in the next example)');
console.log('3. Install dependencies: express and express-session');
console.log('4. Start your server');

