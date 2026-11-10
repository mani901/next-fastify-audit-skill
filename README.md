# next-fastify-audit-skill

**One agent skill that audits your Next.js App Router + Fastify codebase for security, performance, and API-design issues, including LLM-integration risks, and only reports findings it can prove from your code.**

## What it audits

- [x] **Security (Next.js):** hardcoded secrets, `dangerouslySetInnerHTML`, missing auth on route handlers and server actions, `eval()`, error leaks
- [x] **Security (Fastify):** routes without schema validation, hardcoded JWT secrets, CORS `origin: '*'`, string-concatenated SQL
- [x] **Performance:** raw `<img>` tags, `await` inside loops (N+1 queries), Fastify without compression
- [x] **API design:** missing input validation, inconsistent error shapes, error responses that leak internals
- [x] **LLM integration:** API keys in prompts/logs/tool outputs, user input concatenated into system prompts, LLM endpoints with no rate limit or token cap

Every finding ships with severity, `file:line` evidence, and a concrete fix (with a code snippet where possible). Every finding must be verified against the actual code before it is reported. No unverified claims.

## Install (30 seconds)

```bash
# Claude Code
mkdir -p ~/.claude/skills && cp -r next-fastify-audit-skill ~/.claude/skills/

# Cursor
cp -r next-fastify-audit-skill .cursor/skills/

# Codex
cp -r next-fastify-audit-skill ~/.codex/skills/
```

No dependencies, no build step, no API keys. The scanner is plain Node.js (v18+) with zero packages.

## Usage

Just ask your agent:

> Audit this repo for security, performance, and API issues.

Or run the scanner directly:

```bash
node scripts/scan.js ./my-app --json audit-findings.json
node scripts/report.js audit-findings.json audit-report.md
```

## Example output

Auditing the bundled fixture (a small app with planted issues) produces:

```
Scanned 7 files: 8 high, 12 medium, 3 low.
```

```markdown
### SEC-001 Hardcoded secret or API key - lib/llm.ts:7

**Evidence:**
const apiKey = 'sk-live-9f2c41d7a8b34e6f9021c55d';

**Fix:** Move the value into an environment variable and read it with
process.env. Never commit real credentials.
```

See the full sample report in [examples/sample-report.md](examples/sample-report.md).

## Why this is different

Most audit skills do one thing: generic security, for any stack. This one is different in five ways:

1. **Stack-specific, not generic.** It knows Next.js App Router (React Server Components, server actions, route handlers, middleware) and Fastify (plugins, hooks, schema validation, compression) as first-class citizens. No existing skill targets this exact stack.
2. **Three audits in one.** Security, performance, and API design in a single pass, so you run one skill instead of three.
3. **Verified findings only.** Every finding must be cross-checked against the actual code before it is reported. The skill has an explicit, mandatory verification step, which cuts the false positives that make most audit output unusable.
4. **LLM-integration audit included.** Prompt-injection surface, secret exposure in prompts and logs, missing rate limits on LLM endpoints, unsafe tool outputs. Built from real LLM-app experience, not a checklist copied from OWASP.
5. **Fixes, not just complaints.** Every finding comes with a concrete fix, usually a code snippet you can paste in.

## How it works

1. **Scan:** `scripts/scan.js` greps the target repo for known risky patterns and writes JSON findings with file and line evidence.
2. **Verify:** the skill instructs the agent to open each flagged file and confirm the issue is real (checking middleware, hooks, and wrappers, not just the flagged line).
3. **Cross-check:** the skill lists the issues no regex can find (trusting client-supplied roles, secrets in prompts, missing rate limits on expensive endpoints) for a manual pass.
4. **Report:** `scripts/report.js` turns verified findings into a Markdown report ordered by severity.

## Project layout

```
SKILL.md                  The skill: instructions, workflow, checklists, output format
scripts/scan.js           First-pass scanner (zero dependencies, outputs JSON)
scripts/report.js         Turns findings JSON into a readable Markdown report
examples/fixture/         Small intentionally-vulnerable Next.js + Fastify app
examples/sample-report.md Audit report produced by running the skill on the fixture
examples/audit-findings.json Raw scanner output for the fixture
```

## Try it on the fixture

```bash
node scripts/scan.js examples/fixture --json /tmp/findings.json
node scripts/report.js /tmp/findings.json /tmp/report.md
```

You should see 23 findings: 8 high, 12 medium, 3 low, including all 16 rule IDs. The clean file `examples/fixture/lib/auth.ts` is not flagged.

## Rules

| ID | Severity | Check |
|----|----------|-------|
| SEC-001 | High | Hardcoded secret or API key |
| SEC-002 | High | dangerouslySetInnerHTML with untrusted input |
| SEC-003 | High | eval() or new Function() with dynamic code |
| SEC-004 | High | SQL built by string concatenation or interpolation |
| SEC-005 | High | Sensitive data written to console logs |
| SEC-006 | Medium | JWT signed/verified with a hardcoded secret |
| SEC-007 | Medium | CORS allows any origin with credentials |
| SEC-008 | Medium | Fastify route without schema validation |
| SEC-009 | Medium | Route handler with no visible auth check |
| SEC-010 | Medium | Route handler with no visible input validation |
| LLM-001 | High | LLM endpoint with no visible rate limiting |
| LLM-002 | High | User input concatenated into an LLM prompt |
| PERF-001 | Low | Raw img tag instead of next/image |
| PERF-002 | Medium | await inside a loop (likely N+1 queries) |
| PERF-003 | Low | Fastify server without compression |
| API-001 | Low | Error response may leak internals |

## License

MIT. See [LICENSE](LICENSE).
