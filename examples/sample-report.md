# Audit Report: fixture

Date: 2026-11-10
Scope: 7 files scanned by next-fastify-audit-skill v1.0.0
Summary: 23 findings, 8 high, 12 medium, 3 low

> Note: these are scanner findings. Each one should be verified against the
> actual code before acting on it. See SKILL.md, Step 3 (verify every finding).

## High severity

### LLM-001 LLM endpoint with no visible rate limiting - app/api/chat/route.ts:5

**Dimension:** llm-integration

**Evidence:**

```
import { askQuestion } from '../../../lib/llm';
```

**Fix:** Rate-limit every LLM endpoint (per user and per IP) and cap tokens per request. With Fastify: await fastify.register(import("@fastify/rate-limit"), { max: 20, timeWindow: "1 minute" }); with Next.js: add a rate-limit check in middleware or in the handler before calling the model.

### SEC-002 dangerouslySetInnerHTML with untrusted input - app/page.tsx:13

**Dimension:** security

**Evidence:**

```
dangerouslySetInnerHTML={{ __html: data.html }}
```

**Fix:** Avoid dangerouslySetInnerHTML. Render the content as React children, or sanitise it first with a library such as DOMPurify and only then inject it.

### SEC-004 SQL built by string concatenation or template interpolation - lib/db.ts:5

**Dimension:** security

**Evidence:**

```
SELECT * FROM users WHERE email = '" +
```

**Fix:** Use parameterised queries (placeholders) instead of building SQL from strings. Example: db.query("SELECT * FROM users WHERE id = $1", [userId])

### SEC-005 Sensitive data written to console logs - lib/db.ts:10

**Dimension:** security

**Evidence:**

```
console.log('Login attempt for', email, 'with password', password)
```

**Fix:** Remove the log line, or log only a redacted value (e.g. the last 4 characters of a token). Logs are often shipped to third-party services.

### SEC-001 Hardcoded secret or API key - lib/llm.ts:8

**Dimension:** security

**Evidence:**

```
apiKey = 'sk-live-9f2c41d7a8b34e6f9021c55d'
```

**Fix:** Move the value into an environment variable and read it with process.env. Never commit real credentials. Example: const apiKey = process.env.OPENAI_API_KEY; if (!apiKey) throw new Error("OPENAI_API_KEY is not set");

### SEC-005 Sensitive data written to console logs - lib/llm.ts:10

**Dimension:** security

**Evidence:**

```
console.log('Starting LLM client with key', apiKey)
```

**Fix:** Remove the log line, or log only a redacted value (e.g. the last 4 characters of a token). Logs are often shipped to third-party services.

### SEC-004 SQL built by string concatenation or template interpolation - server.js:19

**Dimension:** security

**Evidence:**

```
SELECT * FROM users WHERE id = ' +
```

**Fix:** Use parameterised queries (placeholders) instead of building SQL from strings. Example: db.query("SELECT * FROM users WHERE id = $1", [userId])

### SEC-003 eval() or new Function() with dynamic code - server.js:35

**Dimension:** security

**Evidence:**

```
eval(
```

**Fix:** Remove eval / new Function. Use JSON.parse for data, a map of allowed functions for behaviour, or a proper expression parser.

## Medium severity

### SEC-009 Route handler with no visible auth check - app/api/chat/route.ts:7

**Dimension:** security

**Evidence:**

```
export async function POST
```

**Fix:** Check authentication before doing anything sensitive, in the handler, in middleware.ts, or in a Fastify preHandler hook. Example (Next.js): const session = await getServerSession(authOptions); if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

### SEC-010 Route handler with no visible input validation - app/api/chat/route.ts:7

**Dimension:** api-design

**Evidence:**

```
export async function POST
```

**Fix:** Validate input before using it. With Zod: const body = schema.parse(await req.json()); with Fastify: add a schema option to the route. Return 400 with a consistent error shape on invalid input.

### SEC-009 Route handler with no visible auth check - app/api/users/route.ts:4

**Dimension:** security

**Evidence:**

```
export async function POST
```

**Fix:** Check authentication before doing anything sensitive, in the handler, in middleware.ts, or in a Fastify preHandler hook. Example (Next.js): const session = await getServerSession(authOptions); if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

### SEC-010 Route handler with no visible input validation - app/api/users/route.ts:4

**Dimension:** api-design

**Evidence:**

```
export async function POST
```

**Fix:** Validate input before using it. With Zod: const body = schema.parse(await req.json()); with Fastify: add a schema option to the route. Return 400 with a consistent error shape on invalid input.

### SEC-007 CORS allows any origin with credentials - server.js:10

**Dimension:** security

**Evidence:**

```
origin: '*'
```

**Fix:** Restrict CORS to your own origins: origin: ["https://app.example.com"]. Never use origin: "*" together with credentials: true.

### SEC-008 Fastify route without schema validation - server.js:12

**Dimension:** api-design

**Evidence:**

```
fastify.post('/login', async (req, reply) => {   const { email, password } = req.body;   c
```

**Fix:** Add a schema option to the route: fastify.post("/users", { schema: { body: { type: "object", required: ["email"], properties: { email: { type: "string", format: "email" } } } } }, handler)

### SEC-009 Route handler with no visible auth check - server.js:12

**Dimension:** security

**Evidence:**

```
.post(
```

**Fix:** Check authentication before doing anything sensitive, in the handler, in middleware.ts, or in a Fastify preHandler hook. Example (Next.js): const session = await getServerSession(authOptions); if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

### SEC-006 JWT signed or verified with a hardcoded secret - server.js:14

**Dimension:** security

**Evidence:**

```
jwt.sign({ email }, 'secret123'
```

**Fix:** Read the JWT secret from the environment: jwt.sign(payload, process.env.JWT_SECRET). Use a long random secret (32+ characters) and rotate it if it was ever committed.

### SEC-008 Fastify route without schema validation - server.js:18

**Dimension:** api-design

**Evidence:**

```
fastify.get('/users/:id', async (req, reply) => {   const query = 'SELECT * FROM users WHE
```

**Fix:** Add a schema option to the route: fastify.post("/users", { schema: { body: { type: "object", required: ["email"], properties: { email: { type: "string", format: "email" } } } } }, handler)

### SEC-008 Fastify route without schema validation - server.js:24

**Dimension:** api-design

**Evidence:**

```
fastify.get('/users', async (req, reply) => {   const ids = [1, 2, 3];   const users = [];
```

**Fix:** Add a schema option to the route: fastify.post("/users", { schema: { body: { type: "object", required: ["email"], properties: { email: { type: "string", format: "email" } } } } }, handler)

### PERF-002 await inside a loop (likely N+1 queries) - server.js:27

**Dimension:** performance

**Evidence:**

```
for (const id of ids) { const user = await
```

**Fix:** Fetch all rows in one query (e.g. WHERE id IN (...)) or run the calls in parallel with Promise.all instead of awaiting one by one inside the loop.

### SEC-008 Fastify route without schema validation - server.js:34

**Dimension:** api-design

**Evidence:**

```
fastify.post('/run', async (req, reply) => {   const result = eval(req.body.code);   retur
```

**Fix:** Add a schema option to the route: fastify.post("/users", { schema: { body: { type: "object", required: ["email"], properties: { email: { type: "string", format: "email" } } } } }, handler)

## Low severity

### PERF-001 Raw <img> tag instead of next/image - app/page.tsx:14

**Dimension:** performance

**Evidence:**

```
<img src="/hero.jpg" alt="Hero" />
```

**Fix:** Use next/image for automatic optimisation: import Image from "next/image"; <Image src={...} alt="..." width={800} height={600} />

### PERF-003 Fastify server without compression - server.js:7

**Dimension:** performance

**Evidence:**

```
Fastify instance created without @fastify/compress
```

**Fix:** Register compression: await fastify.register(import("@fastify/compress"));

### API-001 Error response may leak internals - server.js:40

**Dimension:** api-design

**Evidence:**

```
reply.status(500).send({ error: error
```

**Fix:** Return a generic error message to the client and log the details server-side. Example: return Response.json({ error: "Internal server error" }, { status: 500 });
