async function callGeminiWithRetry(model, prompt, options = {}) {
  const { maxRetries = 3, baseDelayMs = 10000 } = options;

  let lastError;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await model.generateContent(prompt);
      return result.response.text();
    } catch (err) {
      lastError = err;

      if (isRateLimitError(err)) {
        const rateLimitError = new Error(
          'Usage limit reached for the AI service. Please wait a while before trying again.'
        );
        rateLimitError.cause = err;
        rateLimitError.isRateLimited = true;
        throw rateLimitError;
      }

      const isOverloaded = isOverloadedError(err);
      const isLastAttempt = attempt === maxRetries;

      if (!isOverloaded || isLastAttempt) {
        break;
      }

      const delay = baseDelayMs * Math.pow(2, attempt);
      console.warn(
        `[Gemini] Attempt ${attempt + 1} failed (${err.message}). Retrying in ${delay}ms...`
      );
      await sleep(delay);
    }
  }

  const finalError = new Error(
    'AI analysis is temporarily unavailable due to high demand. Please try again shortly.'
  );
  finalError.cause = lastError;
  finalError.isGeminiUnavailable = true;
  throw finalError;
}

function isOverloadedError(err) {
  const message = err?.message || '';
  return (
    message.includes('503') ||
    message.includes('Service Unavailable') ||
    message.includes('overloaded') ||
    message.includes('high demand')
  );
}

function isRateLimitError(err) {
  const message = err?.message || '';
  return message.includes('429') || message.includes('quota') || message.includes('RESOURCE_EXHAUSTED');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { callGeminiWithRetry };