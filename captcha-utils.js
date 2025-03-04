/**
 * Generates a captcha challenge
 * @returns {Object} Object containing the captcha display text and answer
 */
export function generateCaptcha() {
  // Define character sets for captcha
  const letters = "abcdefghijklmnopqrstuvwxyz"
  const numbers = "0123456789"
  const allChars = letters + letters.toUpperCase() + numbers

  // Generate a random captcha of 5-6 characters
  const length = Math.floor(Math.random() * 2) + 5 // 5-6 characters
  let captchaText = ""

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * allChars.length)
    captchaText += allChars[randomIndex]
  }

  // Apply some visual distortion (in a real implementation, you might use canvas to generate an image)
  const displayText = captchaText
    .split("")
    .map((char) => {
      // Randomly apply some styling to each character
      const styles = [
        `<span style="transform: rotate(${Math.random() * 20 - 10}deg); display: inline-block;">${char}</span>`,
        `<span style="font-size: ${Math.random() * 0.5 + 0.8}em;">${char}</span>`,
        `<span style="margin-left: ${Math.random() * 5}px;">${char}</span>`,
      ]
      return styles[Math.floor(Math.random() * styles.length)]
    })
    .join("")

  return {
    display: displayText,
    answer: captchaText,
  }
}

/**
 * Validates user input against the captcha answer
 * @param {string} userInput - The user's input
 * @param {string} answer - The correct captcha answer
 * @param {Object} options - Validation options
 * @param {boolean} options.caseSensitive - Whether validation should be case sensitive
 * @returns {boolean} Whether the input is valid
 */
export function validate(userInput, answer, options = { caseSensitive: true }) {
  if (!userInput || !answer) return false

  if (options.caseSensitive) {
    return userInput === answer
  } else {
    return userInput.toLowerCase() === answer.toLowerCase()
  }
}

