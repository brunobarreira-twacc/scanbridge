import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { emitJsonSchema, FindingSchema, NormalizedDocumentSchema } from '../../../src/schemas/index.js';
import { digest, normalizedCorpus } from './fixtures.js';

// Copied from specs/04-finding-schema.md "Examples (synthetic)"; only `<64 hex>` is replaced.
const SEMGREP_EXAMPLE = String.raw`{"fingerprint":"v1:<64 hex>","fingerprint_quality":"exact","rule_id":"rules.sql-injection","producer_reference":null,
 "title":{"text":"rules.sql-injection","truncated":false,"original_length":19},
 "description":{"text":"User input reaches a SQL query.","truncated":false,"original_length":31},
 "severity":"high","severity_original":"ERROR","severity_complete":true,"confidence":null,"category":null,
 "references":[],"status":"open","redactions_applied":false,"occurrence_count":1,
 "occurrences":[{"severity":"high","severity_original":"ERROR",
   "source_location":{"path":"src/db.ts","start_line":42,"start_col":3,"end_line":42,"end_col":58},
   "evidence":{"snippet":{"text":"db.query(\"SELECT * FROM t WHERE id=\" + id)","truncated":false,"original_length":42}}}]}`;

const ZAP_EXAMPLE = String.raw`{"fingerprint":"v1:<64 hex>","fingerprint_quality":"exact","rule_id":"10202","producer_reference":"10202",
 "title":{"text":"Absence of Anti-CSRF Tokens","truncated":false,"original_length":27},
 "severity":"medium","severity_original":"Medium","severity_complete":true,
 "confidence":{"text":"Low","truncated":false,"original_length":3},"status":"open","occurrence_count":1,
 "occurrences":[{"severity":"medium","severity_original":"Medium",
   "runtime_location":{"url":"http://127.0.0.1:8080/login","method":"POST","param":""},
   "evidence":{"attack":null,"evidence":{"text":"<form action=\"/login\">","truncated":false,"original_length":22},"message_id":"17"}}]}`;

const withHex = (example: string, seed: string): unknown =>
  JSON.parse(example.replaceAll('<64 hex>', digest(seed)));

describe('spec 04 finding examples', () => {
  const ajv = new Ajv2020({ strict: true });
  const validateDocument = ajv.compile(emitJsonSchema(NormalizedDocumentSchema));

  for (const [name, example] of [
    ['Semgrep', SEMGREP_EXAMPLE],
    ['ZAP', ZAP_EXAMPLE],
  ] as const) {
    it(`${name} example validates as a Finding`, () => {
      const finding = withHex(example, name);
      assert.equal(FindingSchema.safeParse(finding).success, true);
    });

    it(`${name} example validates inside a normalized document`, () => {
      const base = structuredClone(normalizedCorpus[0]?.doc) as Record<string, unknown>;
      base.findings = [withHex(example, name)];
      assert.equal(NormalizedDocumentSchema.safeParse(base).success, true);
      assert.equal(validateDocument(base), true, JSON.stringify(validateDocument.errors));
    });
  }
});
