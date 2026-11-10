// Fixture: intentionally vulnerable LLM chat endpoint.
// Planted issues: calls the LLM with no rate limit (LLM-001),
// no auth check (SEC-009), no input validation (SEC-010).

import { askQuestion } from '../../../lib/llm';

export async function POST(req) {
  const body = await req.json();
  const answer = await askQuestion(body.question);
  return Response.json({ answer });
}
