/**
 * geminiRetry.js
 *
 * Wraps a Gemini `generateContent` call with retry + exponential backoff,
 * specifically to absorb transient 503 "model overloaded / high demand"
 * errors from Gemini's free tier without failing the whole request.
 *
 * Usage: drop this file next to your analyzeIp/Url/Hash/Domain functions,
 * then wrap your existing `model.generateContent(prompt)` call with it.
 */

/**
 * Calls a Gemini model with automatic retry on transient failures.
 *
 * @param {object} model - your Gemini model instance (from GoogleGenerativeAI)
 * @param {string} prompt - the prompt to send
 * @param {object} [options]
 * @param {number} [options.maxRetries=3] - number of retry attempts after the first try
 * @param {number} [options.baseDelayMs=1000] - initial backoff delay, doubles each retry
 * @returns {Promise<string>} the model's text response
 * @throws {Error} if all retries are exhausted, or on a non-retryable error
 */
async function callGeminiWithRetry(model, prompt, options = {}) {
  const { maxRetries = 3, baseDelayMs = 1000 } = options;

  let lastError;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await model.generateContent(prompt);
      return result.response.text();
    } catch (err) {
      lastError = err;

      const isRetryable = isTransientGeminiError(err);
      const isLastAttempt = attempt === maxRetries;

      if (!isRetryable || isLastAttempt) {
        // Either a non-transient error (bad request, auth, etc.)
        // or we've used up all retries — stop and let the caller handle it.
        break;
      }

      const delay = baseDelayMs * Math.pow(2, attempt); // 1s, 2s, 4s, ...
      console.warn(
        `[Gemini] Attempt ${attempt + 1} failed (${err.message}). Retrying in ${delay}ms...`
      );
      await sleep(delay);
    }
  }

  // All retries exhausted (or non-retryable error) — throw a clean error
  // for the route handler to catch and turn into a graceful API response.
  const finalError = new Error(
    'AI analysis is temporarily unavailable due to high demand. Please try again shortly.'
  );
  finalError.cause = lastError;
  finalError.isGeminiUnavailable = true;
  throw finalError;
}

/**
 * Decides whether an error from the Gemini SDK is worth retrying.
 * 503 (overloaded) and 429 (rate limited) are transient — retry these.
 * 400 (bad request), 401/403 (auth) are not — fail fast on these.
 */
function isTransientGeminiError(err) {
  const message = err?.message || '';
  return (
    message.includes('503') ||
    message.includes('429') ||
    message.includes('Service Unavailable') ||
    message.includes('overloaded') ||
    message.includes('high demand')
  );
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { callGeminiWithRetry };