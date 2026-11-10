#!/usr/bin/env node
/**
 * next-fastify-audit-skill report formatter
 *
 * Turns scanner JSON into a readable Markdown audit report, ordered by
 * severity. Findings are candidates: verify each one against the code
 * before sharing the report (see SKILL.md, Step 3).
 *
 * Usage:
 *   node scripts/report.js <findings.json> [report.md]
 *   node scripts/report.js <findings.json> --stdout
 */

const fs = require('fs');
const path = require('path');

const SECTIONS = [
  ['high', 'High severity'],
  ['medium', 'Medium severity'],
  ['low', 'Low severity'],
];

function main() {
  const args = process.argv.slice(2);
  const input = args.find((a) => !a.startsWith('--'));
  const toStdout = args.includes('--stdout');
  const output = args.find((a, i) => i > 0 && !args[i - 1].startsWith('--') && a !== input);

  if (!input) {
    console.error('Usage: node scripts/report.js <findings.json> [report.md] [--stdout]');
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(path.resolve(input), 'utf8'));
  const findings = data.findings || [];
  const date = new Date().toISOString().slice(0, 10);
  const lines = [];

  lines.push(`# Audit Report: ${data.target || 'project'}`);
  lines.push('');
  lines.push(`Date: ${date}`);
  lines.push(`Scope: ${data.scannedFiles || '?'} files scanned by next-fastify-audit-skill v${data.version || '1.0.0'}`);
  lines.push(`Summary: ${data.total || findings.length} findings, ${data.summary?.high ?? 0} high, ${data.summary?.medium ?? 0} medium, ${data.summary?.low ?? 0} low`);
  lines.push('');
  lines.push('> Note: these are scanner findings. Each one should be verified against the');
  lines.push('> actual code before acting on it. See SKILL.md, Step 3 (verify every finding).');
  lines.push('');

  for (const [severity, heading] of SECTIONS) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push(`## ${heading}`);
    lines.push('');
    for (const f of group) {
      lines.push(`### ${f.id} ${f.title} - ${f.file}:${f.line}`);
      lines.push('');
      lines.push(`**Dimension:** ${f.dimension}`);
      lines.push('');
      lines.push('**Evidence:**');
      lines.push('');
      lines.push('```');
      lines.push(f.evidence);
      lines.push('```');
      lines.push('');
      lines.push(`**Fix:** ${f.fix}`);
      lines.push('');
    }
  }

  if (findings.length === 0) {
    lines.push('## No findings');
    lines.push('');
    lines.push('The scanner found nothing to flag in the audited files. This does not');
    lines.push('guarantee the code is secure, it only means no known pattern matched.');
    lines.push('');
  }

  const report = lines.join('\n');
  if (toStdout || !output) {
    process.stdout.write(report);
  } else {
    fs.writeFileSync(path.resolve(output), report);
    console.log(`Wrote report to ${output}`);
  }
}

main();
