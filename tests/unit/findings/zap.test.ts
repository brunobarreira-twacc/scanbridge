import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Candidate } from '../../../src/contracts/adapter.js';
import { METHOD_MAX, PARAM_MAX, PRODUCER_REFERENCE_MAX, URL_MAX } from '../../../src/contracts/limits.js';
import { fingerprintFromMaterial, zap } from '../../../src/core/fingerprints/index.js';
import { buildZap, shuffled, zapCandidate } from './helpers.js';

const withRuntime = (url: string, method = 'POST', param = ''): Candidate =>
  zapCandidate({ location: { runtime: { url, method, param } } });

test('exact ZAP fingerprint uses alertRef, method, normalized target path and param', () => {
  const [finding] = buildZap([zapCandidate()]).findings;
  assert.equal(finding?.fingerprint, fingerprintFromMaterial(zap('10202', '10202', 'POST', '/login', '')));
  assert.equal(finding?.fingerprint_quality, 'exact');
  assert.equal(finding?.producer_reference, '10202');
  assert.equal(finding?.occurrences[0]?.runtime_location?.url, 'http://127.0.0.1:8080/login');
});

for (const [label, value] of [
  ['missing (null)', null],
  ['empty', ''],
  ['not a string', 42],
] as const) {
  test(`alertRef ${label} gives a null producer_reference, an empty material and degraded quality`, () => {
    const candidate = zapCandidate({ producerReference: value as unknown as string });
    const result = buildZap([candidate]);
    const [finding] = result.findings;
    assert.equal(finding?.producer_reference, null);
    assert.equal(finding?.fingerprint_quality, 'degraded');
    assert.equal(finding?.fingerprint, fingerprintFromMaterial(zap('10202', '', 'POST', '/login', '')));
    assert.deepEqual(result.reasons, ['fingerprint_degraded']);
  });
}

test('the string "unknown" is an ordinary alertRef value', () => {
  const [finding] = buildZap([zapCandidate({ producerReference: 'unknown' })]).findings;
  assert.equal(finding?.producer_reference, 'unknown');
  assert.equal(finding?.fingerprint_quality, 'exact');
});

test('methods are uppercased before fingerprinting and storage', () => {
  const lower = buildZap([withRuntime('http://127.0.0.1:8080/login', 'post')]).findings[0];
  const upper = buildZap([withRuntime('http://127.0.0.1:8080/login', 'POST')]).findings[0];
  assert.equal(lower?.fingerprint, upper?.fingerprint);
  assert.equal(lower?.occurrences[0]?.runtime_location?.method, 'POST');
});

test('query values are excluded from the target path; query names are sorted and deduplicated', () => {
  const a = buildZap([withRuntime('http://127.0.0.1:8080/search?y=1&x=2&x=9')]).findings[0];
  const b = buildZap([withRuntime('http://127.0.0.1:8080/search?x=5&y=7')]).findings[0];
  assert.equal(a?.fingerprint, b?.fingerprint);
  assert.equal(a?.occurrences[0]?.runtime_location?.url, 'http://127.0.0.1:8080/search?x&y');
});

test('URL normalization lowercases the origin, drops the default port and resolves dot segments', () => {
  const [finding] = buildZap([withRuntime('HTTP://Example.com:80/a/../login?b=1&a=2')]).findings;
  assert.equal(finding?.occurrences[0]?.runtime_location?.url, 'http://example.com/login?a&b');
  assert.equal(finding?.fingerprint, fingerprintFromMaterial(zap('10202', '10202', 'POST', '/login?a&b', '')));
});

test('a URL that cannot be normalized gets an invalid placeholder for url and target path', () => {
  const result = buildZap([withRuntime('http://user:pw@example.com/login')]);
  const [finding] = result.findings;
  const url = finding?.occurrences[0]?.runtime_location?.url ?? '';
  assert.match(url, /^\[invalid:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
  assert.deepEqual(
    result.diagnostics.map((d) => d.code),
    ['malformed_report'],
  );
  assert.ok(!JSON.stringify(finding).includes('pw'), 'credentials never reach the output');
});

test('an over-limit normalized URL makes both url and target path the same oversized placeholder', () => {
  const result = buildZap([withRuntime(`http://h.example/${'a'.repeat(URL_MAX)}`)]);
  const [finding] = result.findings;
  const runtime = finding?.occurrences[0]?.runtime_location;
  assert.match(runtime?.url ?? '', /^\[oversized:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
  assert.deepEqual(
    result.diagnostics.map((d) => d.code),
    ['resource_limit_exceeded'],
  );
});

test('an over-limit method gives a placeholder method and a degraded fingerprint', () => {
  const [finding] = buildZap([withRuntime('http://127.0.0.1:8080/login', 'M'.repeat(METHOD_MAX + 1))]).findings;
  assert.match(finding?.occurrences[0]?.runtime_location?.method ?? '', /^\[oversized:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
});

test('an over-limit parameter name gives a placeholder and a degraded fingerprint', () => {
  const [finding] = buildZap([withRuntime('http://127.0.0.1:8080/login', 'POST', 'p'.repeat(PARAM_MAX + 1))]).findings;
  assert.match(finding?.occurrences[0]?.runtime_location?.param ?? '', /^\[oversized:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
});

test('an over-limit alertRef gives a placeholder and a degraded fingerprint', () => {
  const [finding] = buildZap([zapCandidate({ producerReference: 'r'.repeat(PRODUCER_REFERENCE_MAX + 1) })]).findings;
  assert.match(finding?.producer_reference ?? '', /^\[oversized:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
});

test('ZAP occurrences carry runtime_location, structured evidence and a plain message_id, never source_location', () => {
  const [finding] = buildZap([zapCandidate({ description: 'Missing token.', evidence: { attack: 'x', evidence: '<form>', message_id: '17' } })]).findings;
  const occurrence = finding?.occurrences[0];
  assert.equal(occurrence?.source_location, undefined);
  assert.deepEqual(occurrence?.evidence.attack, { text: 'x', truncated: false, original_length: 1 });
  assert.deepEqual(occurrence?.evidence.evidence, { text: '<form>', truncated: false, original_length: 6 });
  assert.equal(occurrence?.evidence.message_id, '17');
  assert.deepEqual(finding?.description, { text: 'Missing token.', truncated: false, original_length: 14 });
  assert.deepEqual(finding?.confidence, { text: 'Low', truncated: false, original_length: 3 });
});

test('shuffled ZAP candidates produce identical output', () => {
  const base = [
    zapCandidate({ location: { runtime: { url: 'http://127.0.0.1:8080/b', method: 'GET', param: 'q' } } }),
    zapCandidate({ location: { runtime: { url: 'http://127.0.0.1:8080/a', method: 'GET', param: '' } }, producerReference: null }),
    zapCandidate({ severity: 'unknown', severityOriginal: 'Strange' }),
  ];
  const expected = JSON.stringify(buildZap(base));
  for (const seed of [3, 11]) {
    assert.equal(JSON.stringify(buildZap(shuffled(base, seed))), expected);
  }
});
