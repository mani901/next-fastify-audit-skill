// Fixture: intentionally vulnerable LLM integration.
// Planted issues: hardcoded API key (SEC-001), key logged (SEC-005),
// user input concatenated into the system prompt (LLM-002),
// LLM endpoint with no rate limit (LLM-001, via the route handler below).

import OpenAI from 'openai';

const apiKey = 'sk-live-9f2c41d7a8b34e6f9021c55d';

console.log('Starting LLM client with key', apiKey);

const client = new OpenAI({ apiKey });

export async function askQuestion(userInput) {
  const response = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      {
        role: 'system',
        content: 'You are a helpful assistant. The user says: ' + userInput,
      },
      { role: 'user', content: userInput },
    ],
  });
  return response.choices[0].message.content;
}
