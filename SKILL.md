---
name: next-fastify-audit
description: Audit a Next.js App Router + Fastify codebase for security, performance, and API-design issues, including LLM-integration risks. Use when the user asks to audit, review, or check a Next.js or Fastify project for vulnerabilities, bad patterns, or API mistakes, or when they want a security/performance report on their codebase.
---

# Next.js + Fastify Audit Skill

Audit a Next.js App Router and/or Fastify codebase in three dimensions at once: **security**, **performance**, and **API design**, plus a dedicated **LLM-integration** pass. Every finding must be verified against the actual code before it is reported. No unverified claims, no invented file paths, no guessing.

## When to use this skill

- The user asks for a security audit, code review, or health check of a Next.js or Fastify project.
- The user asks "is this safe?", "what is wrong with my API?", or "review my routes".
- The user wants an audit report for a repo, a folder, or a specific route/handler.
- The user is about to ship or open-source a Next.js + Fastify app and wants a pre-flight check.

## When NOT to use it

- The codebase is not Next.js or Fastify (use a general security skill instead).
- The user only wants a single bug fixed (fix the bug; do not run a full audit).

## Workflow

### Step 1: Scope the target

Ask the user for the target directory if it is not already clear. Confirm whether the audit covers:
1. The whole repo, or only `app/`, `server/`, or specific routes.
2. All three dimensions (security, performance, API design) or a subset.

Default: whole repo, all three dimensions.

### Step 2: Run the scanner

Run the bundled scanner against the target directory:

```bash
node scripts/scan.js <target-dir> --json audit-findings.json
```

The scanner is a first pass only. It flags candidate issues with file and line evidence. It does not decide what is real.

### Step 3: Verify every finding (mandatory)

For each candidate finding, open the flagged file and confirm the issue is real:

- **Hardcoded secret:** confirm the value is a real credential, not a placeholder, test key, or example string (e.g. `"your-api-key-here"`, `"changeme"`, values only in `*.example` files do not count).
- **Missing auth on a route:** confirm no auth check exists anywhere in the handler chain: the handler file, its middleware, and any wrapper/guard it uses. Middleware in `middleware.ts` or a Fastify `preHandler` hook counts as auth.
- **Missing schema/validation:** confirm the route really has no validation (no Zod schema, no Fastify `schema` option, no manual validation) before reporting it.
- **LLM endpoint without rate limiting:** confirm no rate limit exists in the handler, its middleware, or a gateway in front of it.
- **Dangerous patterns (`eval`, `dangerouslySetInnerHTML`, string-concatenated SQL):** confirm the flagged code actually executes with untrusted input. If the input is a hardcoded constant, downgrade the severity and say so.
- **Performance findings:** confirm the pattern is on a real hot path (a page, an API route, a loop over database rows), not dead code or a one-off script.

**Rule: if you cannot verify a finding by reading the code, do not report it.** If verification is inconclusive, list it under "Could not confirm" with the reason, never in the main findings.

### Step 4: Cross-check for false negatives

The scanner catches known patterns. Manually check these, because no regex finds them:

1. **Server actions and route handlers that trust the client:** any `use server` function or route handler that uses client-supplied IDs, roles, or prices without re-checking them server-side.
2. **Secrets in LLM prompts or tool outputs:** API keys, tokens, or user PII passed into prompts, logged, or returned in tool results.
3. **Prompt-injection surface:** any place where untrusted user input is concatenated into an LLM system prompt or tool call.
4. **Missing rate limits on expensive endpoints:** LLM calls, image generation, and email sending must have a limit even if the scanner did not flag them.
5. **Error responses that leak internals:** stack traces, database errors, or ORM messages returned to the client.

### Step 5: Produce the report

Generate the report from the verified findings:

```bash
node scripts/report.js audit-findings.json audit-report.md
```

Then edit the report to add anything found in Step 4 and remove anything that failed verification in Step 3. The report is the deliverable; the scanner output is not.

## Output format

```markdown
# Audit Report: <project name>
Date: <YYYY-MM-DD>
Scope: <directory audited>
Summary: <N> findings - <H> high, <M> medium, <L> low

## High severity
### <Rule ID> <Title> - <file>:<line>
**Evidence:** <the flagged code, quoted>
**Risk:** <what an attacker or a user could actually do>
**Fix:** <concrete fix, with a code snippet where possible>

## Medium severity
... same format ...

## Low severity
... same format ...

## Could not confirm
- <finding> - <why verification was inconclusive>

## Clean checks (optional, max 5)
- <something the audit checked and found fine, e.g. "All Fastify routes use schema validation except ...">
```

## Severity definitions

| Severity | Meaning |
|----------|---------|
| High | Exploitable now, or exposes secrets / user data / unauthenticated access to a sensitive action. Fix before shipping. |
| Medium | Real weakness, but needs an extra condition to exploit (e.g. an attacker already has an account, or the input is partially trusted). Fix soon. |
| Low | Bad practice or a performance smell that costs speed, money, or maintainability, but is not directly exploitable. Fix when convenient. |

## Audit checklists

### Security (Next.js)

- [ ] No hardcoded secrets, API keys, or tokens in source (use `process.env`).
- [ ] No `dangerouslySetInnerHTML` with untrusted input.
- [ ] Every route handler and server action checks auth before doing anything sensitive.
- [ ] No `eval()` or `new Function()` with user input.
- [ ] No stack traces or database errors returned to the client.
- [ ] `fetch()` calls to internal APIs do not forward raw user cookies blindly.

### Security (Fastify)

- [ ] Every route has a `schema` option (body, querystring, params, response).
- [ ] JWT is verified with a secret from the environment, never a hardcoded string.
- [ ] CORS is not `origin: '*'` on routes that use cookies or auth headers.
- [ ] No SQL built by string concatenation; use parameterised queries.
- [ ] `@fastify/rate-limit` (or equivalent) is registered, at least on auth and LLM routes.

### Performance

- [ ] No `<img>` tags in Next.js pages; use `next/image`.
- [ ] No `await` inside loops over database rows (N+1 queries); use a single query or `Promise.all`.
- [ ] `@fastify/compress` (or equivalent) is registered.
- [ ] Server-component `fetch()` calls set explicit caching (`revalidate`, `cache: 'no-store'`) instead of relying on defaults.

### API design

- [ ] Every route validates its input (Zod, Fastify schema, or manual validation) and returns a consistent error shape.
- [ ] POST/PUT/PATCH routes reject unknown fields instead of silently ignoring them.
- [ ] Error responses use proper HTTP status codes and never leak internals.

### LLM integration

- [ ] No API keys or secrets in prompts, logs, or tool outputs.
- [ ] User input is never concatenated into a system prompt; use message roles or delimiters.
- [ ] Every LLM endpoint has a rate limit and a per-request cost/token cap.
- [ ] Tool outputs are validated before being acted on; the model cannot call arbitrary functions.
- [ ] No user PII is sent to a third-party LLM provider without a stated reason.

## Rules of the audit

1. **Verify before reporting.** An unverified finding is not a finding.
2. **Evidence first.** Every finding cites `file:line` and quotes the flagged code.
3. **Fix, don't just complain.** Every finding ships with a concrete fix, ideally a code snippet.
4. **Do not invent.** If a file, line, or behaviour is not in the code you read, do not claim it exists.
5. **Respect scope.** Do not audit `node_modules`, `dist`, `.next`, or vendored code.
