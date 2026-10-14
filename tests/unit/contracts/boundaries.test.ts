import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const FS_IMPORT = /(?:from\s+|require\(\s*|import\(\s*)['"](?:node:)?fs(?:\/promises)?['"]/;
const PURITY = [/process\.env/, /Date\.now/, /new Date\(/];
const NETWORK = [
  /\bfetch\s*\(/,
  /(?:from\s+|require\(\s*|import\(\s*)['"]node:(?:http|https|http2|net|tls|dgram|child_process)['"]/,
];
const REVEAL = /\.reveal\(/;

function listTs(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries.flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? listTs(p) : p.endsWith('.ts') ? [p] : [];
  });
}

/** Returns one message per violation under `root` (the repository root). */
export function findViolations(root: string): string[] {
  const out: string[] = [];
  const isIo = (rel: string) => rel.startsWith(`src${sep}adapters${sep}io${sep}`);
  const files = [
    ...listTs(join(root, 'src', 'core')),
    ...listTs(join(root, 'src', 'adapters')),
  ];
  for (const f of files) {
    const rel = relative(root, f);
    const text = readFileSync(f, 'utf8');
    if (!isIo(rel)) {
      if (FS_IMPORT.test(text)) out.push(`${rel}: imports fs`);
      for (const re of PURITY) if (re.test(text)) out.push(`${rel}: ${re.source}`);
      for (const re of NETWORK) if (re.test(text)) out.push(`${rel}: network or process client`);
    }
    if (!isIo(rel) && REVEAL.test(text)) out.push(`${rel}: .reveal( outside src/adapters/io`);
  }
  // `.reveal(` is allowed only in src/adapters/io/**; check the rest of src too.
  for (const f of listTs(join(root, 'src'))) {
    const rel = relative(root, f);
    if (isIo(rel) || rel.startsWith(`src${sep}core${sep}`) || rel.startsWith(`src${sep}adapters${sep}`)) continue;
    if (rel.startsWith(`src${sep}contracts${sep}`)) continue; // defines reveal()
    if (REVEAL.test(readFileSync(f, 'utf8'))) out.push(`${rel}: .reveal( outside src/adapters/io`);
  }
  return out;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

test('repository sources respect the boundaries (passes on an empty tree)', () => {
  assert.deepEqual(findViolations(repoRoot), []);
});

test('scanner detects each violation and honors the io exemption', () => {
  const root = mkdtempSync(join(tmpdir(), 'boundaries-'));
  const put = (rel: string, body: string) => {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  };
  put('src/core/a.ts', "import { readFileSync } from 'node:fs';\n");
  put('src/core/b.ts', "import fs from 'fs/promises';\n");
  put('src/core/c.ts', 'const e = process.env.X;\n');
  put('src/core/d.ts', 'const t = Date.now();\n');
  put('src/adapters/semgrep/e.ts', 'const t = new Date(0);\n');
  put('src/adapters/zap/f.ts', 'await fetch("http://x");\n');
  put('src/adapters/zap/g.ts', 'const k = key.reveal();\n');
  put('src/cli/h.ts', 'const k = key.reveal();\n');
  put('src/adapters/io/ok.ts', "import fs from 'node:fs';\nconst k = key.reveal();\nawait fetch('x');\nprocess.env.A;\n");
  put('src/contracts/sensitive.ts', 'reveal(): string { return this.v; }\n');
  const v = findViolations(root);
  const files = new Set(v.map((m) => m.split(':')[0]));
  for (const f of ['a', 'b', 'c', 'd'].map((n) => join('src', 'core', `${n}.ts`))) assert.ok(files.has(f), f);
  assert.ok(files.has(join('src', 'adapters', 'semgrep', 'e.ts')));
  assert.ok(files.has(join('src', 'adapters', 'zap', 'f.ts')));
  assert.ok(files.has(join('src', 'adapters', 'zap', 'g.ts')));
  assert.ok(files.has(join('src', 'cli', 'h.ts')));
  assert.equal([...files].some((f) => f?.includes(`${sep}io${sep}`) || f?.includes('contracts')), false);
});
