import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  canonicalizeSnippet,
  fingerprintFromMaterial,
  semgrepDegraded,
  semgrepExact,
  zap,
} from '../../../src/core/fingerprints/fingerprint.js';

// Golden values were computed independently with Python hashlib over the
// RFC 8785 material strings given in the comments.
const SEMGREP_EXACT_GOLDEN = 'v1:f608bc0e2c22e1bfa214d06e15d24b8554d7283e81646a5deed16b205d4b07b6';
const SEMGREP_DEGRADED_GOLDEN = 'v1:8ba06935a897821527274dcfb77449ac66c1436f65ece2b672d372afb4aeae2c';
const ZAP_GOLDEN = 'v1:bc03584f03d28e26147cc710c53082943e49a9f46da99065bdea90c47b575e13';

const SNIPPET = 'db.query("SELECT * FROM t WHERE id=" + id)';

test('golden fingerprint: Semgrep exact', () => {
  // ["semgrep","rules.sql-injection","src/db.ts","db.query(\"SELECT * FROM t WHERE id=\" + id)"]
  const material = semgrepExact('rules.sql-injection', 'src/db.ts', canonicalizeSnippet(SNIPPET));
  assert.equal(fingerprintFromMaterial(material), SEMGREP_EXACT_GOLDEN);
});

test('golden fingerprint: Semgrep degraded', () => {
  // ["semgrep","rules.sql-injection","src/db.ts",42,3,42,58]
  const material = semgrepDegraded('rules.sql-injection', 'src/db.ts', 42, 3, 42, 58);
  assert.equal(fingerprintFromMaterial(material), SEMGREP_DEGRADED_GOLDEN);
});

test('golden fingerprint: ZAP', () => {
  // ["zap","10202","10202","POST","/login",""]
  assert.equal(fingerprintFromMaterial(zap('10202', '10202', 'POST', '/login', '')), ZAP_GOLDEN);
});

test('fingerprint has the v1 prefix and 64 lowercase hex digits', () => {
  assert.match(fingerprintFromMaterial(['a']), /^v1:[0-9a-f]{64}$/);
});

test('snippet fingerprint ignores whitespace, line endings and BOM differences', () => {
  const reference = fingerprintFromMaterial(semgrepExact('r', 'a.ts', canonicalizeSnippet('x = 1;\ny = 2;')));
  const variants = ['x = 1;\r\ny = 2;', '﻿x = 1;\ny = 2;', '  x   =  1;\t\n\ty = 2;  \n', 'x = 1;\ry = 2;'];
  for (const variant of variants) {
    assert.equal(
      fingerprintFromMaterial(semgrepExact('r', 'a.ts', canonicalizeSnippet(variant))),
      reference,
      JSON.stringify(variant),
    );
  }
});

test('snippet fingerprint is stable when line numbers change', () => {
  // Exact material has no line numbers, so moving the code leaves identity unchanged.
  const before = fingerprintFromMaterial(semgrepExact('r', 'a.ts', canonicalizeSnippet(SNIPPET)));
  const after = fingerprintFromMaterial(semgrepExact('r', 'a.ts', canonicalizeSnippet(`\n\n\n${SNIPPET}`)));
  assert.equal(before, after);
});

test('different snippets, rules or paths give different fingerprints', () => {
  const base = fingerprintFromMaterial(semgrepExact('r', 'a.ts', canonicalizeSnippet('x = 1;')));
  assert.notEqual(base, fingerprintFromMaterial(semgrepExact('r', 'a.ts', canonicalizeSnippet('x = 2;'))));
  assert.notEqual(base, fingerprintFromMaterial(semgrepExact('other', 'a.ts', canonicalizeSnippet('x = 1;'))));
  assert.notEqual(base, fingerprintFromMaterial(semgrepExact('r', 'b.ts', canonicalizeSnippet('x = 1;'))));
});

test('exact and degraded material never collide for the same rule and path', () => {
  assert.notEqual(
    fingerprintFromMaterial(semgrepExact('r', 'a.ts', 'x')),
    fingerprintFromMaterial(semgrepDegraded('r', 'a.ts', 1, 1, 1, 2)),
  );
});

test('material strings are NFC-normalized before hashing', () => {
  const composed = fingerprintFromMaterial(['zap', 'é']);
  const decomposed = fingerprintFromMaterial(['zap', 'é']);
  assert.equal(composed, decomposed);
});

test('canonicalizeSnippet: BOM, NFC, line endings, whitespace and trim', () => {
  assert.equal(canonicalizeSnippet('﻿  a\r\n\tb\rc  '), 'a b c');
  assert.equal(canonicalizeSnippet('é'), 'é');
  assert.equal(canonicalizeSnippet('a  b'), 'a b');
  assert.equal(canonicalizeSnippet('  \n  '), '');
});

test('canonicalizeSnippet keeps a non-leading BOM as content, collapsed as whitespace', () => {
  assert.equal(canonicalizeSnippet('a﻿b'), 'a b');
});

test('fingerprintFromMaterial rejects float material', () => {
  assert.throws(() => fingerprintFromMaterial(['semgrep', 1.5]), TypeError);
});
