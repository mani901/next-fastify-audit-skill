#!/usr/bin/env node
/**
 * next-fastify-audit-skill scanner
 *
 * First-pass static scan of a Next.js App Router + Fastify codebase.
 * Flags candidate issues with file:line evidence and writes them as JSON.
 * The scanner does NOT decide what is real - the skill requires every
 * finding to be verified against the actual code before it is reported.
 *
 * Usage:
 *   node scripts/scan.js <target-dir> [--json out.json] [--quiet]
 *
 * Exit codes: 0 = scan completed (even if findings exist), 1 = usage error.
 */

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.turbo', 'out',
]);
const SCAN_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };

// Values that look like secrets but are placeholders, test data, or examples.
const PLACEHOLDER_SECRET = /^(your[-_ ]?(api[-_ ]?)?key|changeme|placeholder|example|test|dummy|xxx+|todo|xxx[-_ ]?key|sk-test|pk_test_)/i;

const RULES = [
  {
    id: 'SEC-001',
    severity: 'high',
    title: 'Hardcoded secret or API key',
    dimension: 'security',
    fix: 'Move the value into an environment variable and read it with process.env. Never commit real credentials. Example: const apiKey = process.env.OPENAI_API_KEY; if (!apiKey) throw new Error("OPENAI_API_KEY is not set");',
    test: (content, file) => {
      const findings = [];
      const re = /(api[_-]?key|secret|password|passwd|access[_-]?token|private[_-]?key)\s*[:=]\s*['"]([^'"]{6,})['"]/gi;
      let m;
      while ((m = re.exec(content)) !== null) {
        if (PLACEHOLDER_SECRET.test(m[2])) continue;
        if (/\bprocess\.env\b/.test(content.slice(Math.max(0, m.index - 60), m.index))) continue;
        findings.push({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) });
      }
      return findings;
    },
  },
  {
    id: 'SEC-002',
    severity: 'high',
    title: 'dangerouslySetInnerHTML with untrusted input',
    dimension: 'security',
    fix: 'Avoid dangerouslySetInnerHTML. Render the content as React children, or sanitise it first with a library such as DOMPurify and only then inject it.',
    test: (content) => findAll(content, /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*\}\s*\}/g,
      (m) => ({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) })),
  },
  {
    id: 'SEC-003',
    severity: 'high',
    title: 'eval() or new Function() with dynamic code',
    dimension: 'security',
    fix: 'Remove eval / new Function. Use JSON.parse for data, a map of allowed functions for behaviour, or a proper expression parser.',
    test: (content) => findAll(content, /\beval\s*\(|new\s+Function\s*\(/g,
      (m) => ({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) })),
  },
  {
    id: 'SEC-004',
    severity: 'high',
    title: 'SQL built by string concatenation or template interpolation',
    dimension: 'security',
    fix: 'Use parameterised queries (placeholders) instead of building SQL from strings. Example: db.query("SELECT * FROM users WHERE id = $1", [userId])',
    test: (content) => {
      const findings = [];
      const re = /\b(SELECT|INSERT|UPDATE|DELETE)\b[^;]{0,120}?(\+|\$\{)/g;
      let m;
      while ((m = re.exec(content)) !== null) {
        // Skip parameterised queries: $1, $2 ... are placeholders, not interpolation.
        const tail = content.slice(m.index, m.index + 140);
        if (/\$\d+\b/.test(tail) && !/\$\{/.test(tail)) continue;
        findings.push({ line: lineOf(content, m.index), evidence: m[0].replace(/\s+/g, ' ').trim().slice(0, 120) });
      }
      return findings;
    },
  },
  {
    id: 'SEC-005',
    severity: 'high',
    title: 'Sensitive data written to console logs',
    dimension: 'security',
    fix: 'Remove the log line, or log only a redacted value (e.g. the last 4 characters of a token). Logs are often shipped to third-party services.',
    test: (content) => findAll(
      content,
      /console\.(log|info|debug|warn|error)\s*\([^)]*(password|secret|api[_-]?key|access[_-]?token|authorization|credit[_-]?card)[^)]*\)/gi,
      (m) => ({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) })),
  },
  {
    id: 'SEC-006',
    severity: 'medium',
    title: 'JWT signed or verified with a hardcoded secret',
    dimension: 'security',
    fix: 'Read the JWT secret from the environment: jwt.sign(payload, process.env.JWT_SECRET). Use a long random secret (32+ characters) and rotate it if it was ever committed.',
    test: (content) => {
      const findings = [];
      const re = /jwt\.(sign|verify)\s*\([^,]+,\s*['"]([^'"]+)['"]/g;
      let m;
      while ((m = re.exec(content)) !== null) {
        if (PLACEHOLDER_SECRET.test(m[2])) continue;
        findings.push({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) });
      }
      return findings;
    },
  },
  {
    id: 'SEC-007',
    severity: 'medium',
    title: 'CORS allows any origin with credentials',
    dimension: 'security',
    fix: 'Restrict CORS to your own origins: origin: ["https://app.example.com"]. Never use origin: "*" together with credentials: true.',
    test: (content) => findAll(content, /origin\s*:\s*['"]\*['"]/g,
      (m) => ({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) })),
  },
  {
    id: 'SEC-008',
    severity: 'medium',
    title: 'Fastify route without schema validation',
    dimension: 'api-design',
    fix: 'Add a schema option to the route: fastify.post("/users", { schema: { body: { type: "object", required: ["email"], properties: { email: { type: "string", format: "email" } } } } }, handler)',
    test: (content) => {
      const findings = [];
      const re = /\b\w+\.(get|post|put|patch|delete)\s*\(/g;
      let m;
      while ((m = re.exec(content)) !== null) {
        const window = content.slice(m.index, m.index + 600);
        const callEnd = window.indexOf('async');
        const head = callEnd === -1 ? window : window.slice(0, callEnd);
        if (!/\bschema\s*:/.test(head) && !/schema\s*:/.test(window.slice(0, 300))) {
          findings.push({ line: lineOf(content, m.index), evidence: content.slice(m.index, m.index + 90).replace(/\n/g, ' ').trim() });
        }
      }
      return findings;
    },
  },
  {
    id: 'SEC-009',
    severity: 'medium',
    title: 'Route handler with no visible auth check',
    dimension: 'security',
    fix: 'Check authentication before doing anything sensitive, in the handler, in middleware.ts, or in a Fastify preHandler hook. Example (Next.js): const session = await getServerSession(authOptions); if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });',
    test: (content, file) => {
      const isRoute = /app[\\/]api[\\/]/.test(file) || /routes?[\\/]/.test(file) || /server\.(js|ts)$/.test(file);
      if (!isRoute) return [];
      const hasHandler = /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b/.test(content)
        || /\.(get|post|put|patch|delete)\s*\(/.test(content);
      if (!hasHandler) return [];
      const hasAuth = /\b(auth|session|getServerSession|jwt\.verify|verifyToken|requireAuth|isAuthenticated|preHandler)\b/i.test(content);
      if (hasAuth) return [];
      const m = content.match(/export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b|\.(get|post|put|patch|delete)\s*\(/);
      return [{ line: m ? lineOf(content, m.index) : 1, evidence: (m ? m[0] : 'route handler').trim().slice(0, 120) }];
    },
  },
  {
    id: 'SEC-010',
    severity: 'medium',
    title: 'Route handler with no visible input validation',
    dimension: 'api-design',
    fix: 'Validate input before using it. With Zod: const body = schema.parse(await req.json()); with Fastify: add a schema option to the route. Return 400 with a consistent error shape on invalid input.',
    test: (content, file) => {
      const isRoute = /app[\\/]api[\\/]/.test(file);
      if (!isRoute) return [];
      const hasHandler = /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b/.test(content);
      if (!hasHandler) return [];
      const hasValidation = /\b(zod|z\.object|\.parse\(|schema|validate|validator)\b/i.test(content);
      if (hasValidation) return [];
      const m = content.match(/export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b/);
      return [{ line: m ? lineOf(content, m.index) : 1, evidence: (m ? m[0] : 'route handler').trim().slice(0, 120) }];
    },
  },
  {
    id: 'LLM-001',
    severity: 'high',
    title: 'LLM endpoint with no visible rate limiting',
    dimension: 'llm-integration',
    fix: 'Rate-limit every LLM endpoint (per user and per IP) and cap tokens per request. With Fastify: await fastify.register(import("@fastify/rate-limit"), { max: 20, timeWindow: "1 minute" }); with Next.js: add a rate-limit check in middleware or in the handler before calling the model.',
    test: (content, file) => {
      const isRoute = /app[\\/]api[\\/]/.test(file) || /routes?[\\/]/.test(file) || /server\.(js|ts)$/.test(file);
      if (!isRoute) return [];
      const usesLlm = /\b(openai|anthropic|gemini|groq|chat\.completions|messages\.create|generateText|llm|createChatCompletion)\b/i.test(content);
      if (!usesLlm) return [];
      const hasLimit = /\b(rateLimit|rate-limit|rate_limit|throttle|limiter)\b/i.test(content);
      if (hasLimit) return [];
      const m = content.match(/\b(openai|anthropic|gemini|groq|chat\.completions|messages\.create|generateText|llm|createChatCompletion)\b/i);
      const lineNo = m ? lineOf(content, m.index) : 1;
      const lineText = content.split('\n')[lineNo - 1]?.trim() || 'LLM call';
      return [{ line: lineNo, evidence: lineText.slice(0, 120) }];
    },
  },
  {
    id: 'LLM-002',
    severity: 'high',
    title: 'User input concatenated into an LLM prompt',
    dimension: 'llm-integration',
    fix: 'Never build a system prompt by string concatenation with user input. Pass user input as a separate user-role message, or wrap it in delimiters and instruct the model to treat it as data, not instructions.',
    test: (content) => {
      const findings = [];
      const patterns = [
        /system\s*:\s*[`'"][^`'"]*[`'"]\s*\+/g,
        /system\s*:\s*`[^`]*\$\{/g,
        /prompt\s*[:=]\s*[`'"][^`'"]*[`'"]\s*\+/g,
      ];
      for (const re of patterns) {
        let m;
        while ((m = re.exec(content)) !== null) {
          findings.push({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) });
        }
      }
      return findings;
    },
  },
  {
    id: 'PERF-001',
    severity: 'low',
    title: 'Raw <img> tag instead of next/image',
    dimension: 'performance',
    fix: 'Use next/image for automatic optimisation: import Image from "next/image"; <Image src={...} alt="..." width={800} height={600} />',
    test: (content, file) => {
      if (!/app[\\/]/.test(file) && !/\.tsx$/.test(file)) return [];
      return findAll(content, /<img\s[^>]*>/g,
        (m) => ({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) }));
    },
  },
  {
    id: 'PERF-002',
    severity: 'medium',
    title: 'await inside a loop (likely N+1 queries)',
    dimension: 'performance',
    fix: 'Fetch all rows in one query (e.g. WHERE id IN (...)) or run the calls in parallel with Promise.all instead of awaiting one by one inside the loop.',
    test: (content) => {
      const findings = [];
      const re = /\b(for|while)\s*\([^)]*\)\s*\{[^}]{0,400}?\bawait\b/g;
      let m;
      while ((m = re.exec(content)) !== null) {
        findings.push({ line: lineOf(content, m.index), evidence: m[0].replace(/\s+/g, ' ').trim().slice(0, 120) });
      }
      return findings;
    },
  },
  {
    id: 'PERF-003',
    severity: 'low',
    title: 'Fastify server without compression',
    dimension: 'performance',
    fix: 'Register compression: await fastify.register(import("@fastify/compress"));',
    test: (content, file) => {
      if (!/server\.(js|ts)$/.test(file)) return [];
      if (!/fastify/.test(content)) return [];
      if (/compress/.test(content)) return [];
      const m = content.match(/fastify/);
      return [{ line: m ? lineOf(content, m.index) : 1, evidence: 'Fastify instance created without @fastify/compress' }];
    },
  },
  {
    id: 'API-001',
    severity: 'low',
    title: 'Error response may leak internals',
    dimension: 'api-design',
    fix: 'Return a generic error message to the client and log the details server-side. Example: return Response.json({ error: "Internal server error" }, { status: 500 });',
    test: (content) => findAll(
      content,
      /(Response\.json|reply(\.status\(\d+\))?\.send|res(\.status\(\d+\))?\.json)\s*\(\s*\{[^}]*\b(error|message)\s*:\s*(err|error|e)\b/g,
      (m) => ({ line: lineOf(content, m.index), evidence: m[0].trim().slice(0, 120) })),
  },
];

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

function findAll(content, re, map) {
  const out = [];
  let m;
  re.lastIndex = 0;
  while ((m = re.exec(content)) !== null) out.push(map(m));
  return out;
}

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out);
    } else if (entry.isFile() && SCAN_EXTS.has(path.extname(entry.name))) {
      out.push(full);
    }
  }
  return out;
}

function stripComments(content) {
  // Replace comment text with spaces, preserving newlines so line numbers
  // stay correct. Prevents words in comments (e.g. "auth", "eval") from
  // fooling the auth/pattern checks.
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
}

function scanFile(file, root) {
  const raw = fs.readFileSync(file, 'utf8');
  const content = stripComments(raw);
  const rel = path.relative(root, file);
  const findings = [];
  for (const rule of RULES) {
    let hits = [];
    try {
      hits = rule.test(content, rel) || [];
    } catch {
      hits = [];
    }
    for (const hit of hits) {
      findings.push({
        id: rule.id,
        severity: rule.severity,
        dimension: rule.dimension,
        title: rule.title,
        file: rel.split(path.sep).join('/'),
        line: hit.line,
        evidence: hit.evidence,
        fix: rule.fix,
      });
    }
  }
  return findings;
}

function main() {
  const args = process.argv.slice(2);
  const target = args.find((a) => !a.startsWith('--'));
  const jsonIdx = args.indexOf('--json');
  const jsonOut = jsonIdx !== -1 ? args[jsonIdx + 1] : null;
  const quiet = args.includes('--quiet');

  if (!target) {
    console.error('Usage: node scripts/scan.js <target-dir> [--json out.json] [--quiet]');
    process.exit(1);
  }

  const root = path.resolve(target);
  if (!fs.existsSync(root)) {
    console.error(`Target does not exist: ${root}`);
    process.exit(1);
  }

  const files = walk(root, []);
  let findings = [];
  for (const file of files) findings = findings.concat(scanFile(file, root));

  findings.sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    || a.file.localeCompare(b.file)
    || a.line - b.line);

  const summary = {
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  const result = {
    tool: 'next-fastify-audit-skill scanner',
    version: '1.0.0',
    target: path.basename(root),
    scannedFiles: files.length,
    summary,
    total: findings.length,
    findings,
  };

  if (jsonOut) {
    fs.writeFileSync(path.resolve(jsonOut), JSON.stringify(result, null, 2) + '\n');
    if (!quiet) console.log(`Wrote ${findings.length} findings to ${jsonOut}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
  if (!quiet) {
    console.log(`Scanned ${files.length} files: ${summary.high} high, ${summary.medium} medium, ${summary.low} low.`);
  }
}

main();
