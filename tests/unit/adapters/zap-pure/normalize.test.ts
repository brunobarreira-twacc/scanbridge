import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { NormalizeContext, RawDiagnostic } from '../../../../src/contracts/adapter.js';
import type { JsonValue } from '../../../../src/contracts/enums.js';
import { normalize } from '../../../../src/adapters/zap/normalize.js';
import { parse } from '../../../../src/adapters/zap/parse.js';
import { alert, LIVE_CONTEXT, NO_SOURCES, shuffled, TARGET_ORIGIN } from './helpers.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..', 'tests', 'fixtures', 'zap');

const OFFLINE_CONTEXT: NormalizeContext = { ...LIVE_CONTEXT, mode: 'offline' };
const LOSS: RawDiagnostic = { code: 'tool_timeout', level: 'warn', tool: 'zap', message: 'Spider deadline reached' };

function docOf(alerts: unknown[]): JsonValue {
  return { alerts } as JsonValue;
}

function fixtureDoc(name: string): JsonValue {
  const result = parse(readFileSync(join(FIXTURES, name, 'raw.json')));
  assert.ok(result.ok, `${name} parses`);
  return result.doc;
}

test('live without coverage loss is complete', () => {
  const out = normalize(docOf([alert()]), LIVE_CONTEXT, NO_SOURCES);
  assert.equal(out.completeness, 'complete');
  assert.deepEqual(out.reasons, []);
});

test('live with coverage loss is partial, and the loss comes back in coverageLoss', () => {
  const out = normalize(docOf([alert()]), { ...LIVE_CONTEXT, coverageLoss: [LOSS] }, NO_SOURCES);
  assert.equal(out.completeness, 'partial');
  assert.deepEqual(out.coverageLoss, [LOSS]);
  assert.deepEqual(out.reasons, []);
});

test('offline is unverified with reason offline_report, even for an otherwise clean dump', () => {
  const out = normalize(docOf([alert()]), OFFLINE_CONTEXT, NO_SOURCES);
  assert.equal(out.completeness, 'unverified');
  assert.deepEqual(out.reasons, ['offline_report']);
  assert.equal(out.candidates.length, 1);
});

test('offline with an empty dump is still unverified', () => {
  const out = normalize(docOf([]), OFFLINE_CONTEXT, NO_SOURCES);
  assert.equal(out.completeness, 'unverified');
  assert.deepEqual(out.reasons, ['offline_report']);
});

test('the same dump gives the same live and offline candidates; only completeness differs', () => {
  const doc = fixtureDoc('normal');
  const live = normalize(doc, LIVE_CONTEXT, NO_SOURCES);
  const offline = normalize(doc, OFFLINE_CONTEXT, NO_SOURCES);
  assert.deepEqual(offline.candidates, live.candidates);
  assert.equal(live.completeness, 'complete');
  assert.equal(offline.completeness, 'unverified');
});

test('producerVersion and the severity mapping version are carried through', () => {
  const out = normalize(docOf([]), { ...LIVE_CONTEXT, producerVersion: '2.15.0' }, NO_SOURCES);
  assert.equal(out.producerVersion, '2.15.0');
  assert.equal(out.severityMappingVersion, 'zap-1');
});

test('a null targetOrigin skips the scope check', () => {
  const out = normalize(docOf([alert({ url: 'http://elsewhere.example/' })]), { ...LIVE_CONTEXT, targetOrigin: null }, NO_SOURCES);
  assert.equal(out.candidates.length, 1);
  assert.deepEqual(out.diagnostics, []);
});

test('a dump that is not {"alerts":[...]} gives failed with malformed_report and no candidates', () => {
  const out = normalize({ site: [] } as JsonValue, LIVE_CONTEXT, NO_SOURCES);
  assert.equal(out.completeness, 'failed');
  assert.deepEqual(out.candidates, []);
  assert.deepEqual(
    out.diagnostics.map((d) => d.code),
    ['malformed_report'],
  );
});

test('redaction is reported on the candidate whose alert index was touched', () => {
  const doc = fixtureDoc('normal');
  const ctx = { ...LIVE_CONTEXT, redactionTouched: new Set(['/alerts/0/url']) };
  const out = normalize(doc, ctx, NO_SOURCES);
  const touched = out.candidates.filter((c) => c.redactionsApplied).map((c) => c.ruleId);
  assert.deepEqual(touched, ['10202']);
});

test('a pointer to the whole alert also marks that alert', () => {
  const doc = fixtureDoc('normal');
  const ctx = { ...LIVE_CONTEXT, redactionTouched: new Set(['/alerts/1']) };
  const out = normalize(doc, ctx, NO_SOURCES);
  assert.deepEqual(
    out.candidates.filter((c) => c.redactionsApplied).map((c) => c.ruleId),
    ['10038'],
  );
});

test('the same dump twice gives byte-identical output', () => {
  const doc = fixtureDoc('duplicates');
  assert.equal(JSON.stringify(normalize(doc, LIVE_CONTEXT, NO_SOURCES)), JSON.stringify(normalize(doc, LIVE_CONTEXT, NO_SOURCES)));
});

for (const name of ['normal', 'duplicates', 'unknown-risk', 'out-of-scope', 'malformed-entries', 'numeric-strings']) {
  test(`shuffled alert order gives identical output for ${name}`, () => {
    const alerts = (fixtureDoc(name) as { alerts: unknown[] }).alerts;
    const expected = JSON.stringify(normalize(docOf(alerts), LIVE_CONTEXT, NO_SOURCES));
    for (const seed of [1, 7, 42, 1234]) {
      assert.equal(JSON.stringify(normalize(docOf(shuffled(alerts, seed)), LIVE_CONTEXT, NO_SOURCES)), expected, `seed ${seed}`);
    }
  });
}

test('identical alerts collapse to one candidate and differing messageId keeps both', () => {
  const same = alert({ pluginId: '10202', alertRef: '10202-1', name: 'Absence of Anti-CSRF Tokens', risk: 'Medium', url: `${TARGET_ORIGIN}/login` });
  const out = normalize(docOf([same, { ...same }, { ...same, messageId: '18' }]), LIVE_CONTEXT, NO_SOURCES);
  assert.equal(out.candidates.length, 2);
});

test('an unusable entry is counted once per entry and never becomes a candidate', () => {
  const out = normalize(docOf([{ url: `${TARGET_ORIGIN}/` }, { pluginId: '10038' }, 'x']), LIVE_CONTEXT, NO_SOURCES);
  assert.equal(out.unusableCount, 3);
  assert.deepEqual(out.candidates, []);
  assert.deepEqual(
    out.diagnostics.map((d) => d.code),
    ['malformed_report'],
  );
});

test('out-of-scope and uncheckable URLs are counted in one out_of_scope_target diagnostic', () => {
  const out = normalize(
    docOf([alert({ url: 'http://127.0.0.1:9090/' }), alert({ url: 'http://127.0.0.1:8080/a\u0001' }), alert({ url: 'not a url' })]),
    LIVE_CONTEXT,
    NO_SOURCES,
  );
  assert.equal(out.candidates.length, 0);
  assert.deepEqual(
    out.diagnostics.map((d) => [d.code, d.message.startsWith('3 alerts')]),
    [['out_of_scope_target', true]],
  );
});

test('a mapped risk and an unknown one both appear, with unmapped_severity once', () => {
  const out = normalize(docOf([alert({ risk: 'Critical' }), alert({ risk: 'High', pluginId: '10202' })]), LIVE_CONTEXT, NO_SOURCES);
  assert.deepEqual(
    out.candidates.map((c) => c.severity),
    ['unknown', 'high'],
  );
  assert.deepEqual(
    out.diagnostics.map((d) => d.code),
    ['unmapped_severity'],
  );
});
