import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { NormalizeContext, RawDiagnostic } from '../../../../src/contracts/adapter.js';
import type { JsonValue } from '../../../../src/contracts/enums.js';
import type { SourceText } from '../../../../src/contracts/ports.js';
import { normalize } from '../../../../src/adapters/sonarqube/normalize.js';
import { mapSeverity } from '../../../../src/adapters/sonarqube/severity.js';

const NO_SOURCES: ReadonlyMap<string, SourceText> = new Map();

const CTX: NormalizeContext = {
  mode: 'live',
  targetRel: '',
  targetOrigin: null,
  producerVersion: null,
  redactionTouched: new Set(),
  coverageLoss: [],
  scanDiagnostics: [],
  scanReasons: [],
};

function doc(issues: unknown[], projectKey = 'proj'): JsonValue {
  return { issues, total: issues.length, projectKey } as JsonValue;
}

function issue(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    key: 'KEY-1',
    rule: 'javasecurity:S3649',
    component: 'proj:src/App.java',
    type: 'VULNERABILITY',
    message: 'SQL injection.',
    impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }],
    ...over,
  };
}

test('severity mapping table: BLOCKER→critical, HIGH→high, MEDIUM→medium, LOW→low, INFO→info, other→unknown', () => {
  assert.equal(mapSeverity('BLOCKER'), 'critical');
  assert.equal(mapSeverity('HIGH'), 'high');
  assert.equal(mapSeverity('MEDIUM'), 'medium');
  assert.equal(mapSeverity('LOW'), 'low');
  assert.equal(mapSeverity('INFO'), 'info');
  assert.equal(mapSeverity('UNKNOWN'), 'unknown');
  assert.equal(mapSeverity('blocker'), 'unknown');
  assert.equal(mapSeverity(''), 'unknown');
});

test('VULNERABILITY uses SECURITY impact', () => {
  const out = normalize(doc([issue({ type: 'VULNERABILITY', impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }, { softwareQuality: 'RELIABILITY', severity: 'BLOCKER' }] })]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.severityOriginal, 'HIGH');
});

test('BUG uses RELIABILITY impact', () => {
  const out = normalize(doc([issue({ type: 'BUG', impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }, { softwareQuality: 'RELIABILITY', severity: 'BLOCKER' }] })]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.severityOriginal, 'BLOCKER');
});

test('fallback to highest impact when preferred quality is absent', () => {
  const out = normalize(doc([issue({ type: 'VULNERABILITY', impacts: [{ softwareQuality: 'RELIABILITY', severity: 'BLOCKER' }, { softwareQuality: 'MAINTAINABILITY', severity: 'LOW' }] })]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.severityOriginal, 'BLOCKER');
});

test('field mapping: ruleId, producerReference, producerFingerprint, title, category', () => {
  const out = normalize(doc([issue({ key: 'K1', rule: 'java:S2259', hash: 'fp123', message: 'NPE!', type: 'BUG' })]), CTX, NO_SOURCES);
  const c = out.candidates[0]!;
  assert.equal(c.ruleId, 'java:S2259');
  assert.equal(c.producerReference, 'K1');
  assert.equal(c.producerFingerprint, 'fp123');
  assert.equal(c.title, 'NPE!');
  assert.equal(c.category, 'BUG');
  assert.equal(c.producer, 'sonarqube');
  assert.equal(c.description, null);
  assert.equal(c.confidence, null);
  assert.deepEqual(c.references, []);
});

test('hash absent → producerFingerprint null', () => {
  const out = normalize(doc([issue()]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.producerFingerprint, null);
});

test('component path extraction: strips projectKey: prefix', () => {
  const out = normalize(doc([issue({ component: 'proj:src/main/java/App.java', line: 1 })]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.location.source?.path, 'src/main/java/App.java');
});

test('component without projectKey prefix is used as-is', () => {
  const out = normalize(doc([issue({ component: 'other-proj:src/App.java', line: 1 })]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.location.source?.path, 'other-proj:src/App.java');
});

test('location from textRange (preferred)', () => {
  const out = normalize(doc([issue({ textRange: { startLine: 10, startOffset: 4, endLine: 10, endOffset: 20 }, line: 99 })]), CTX, NO_SOURCES);
  const loc = out.candidates[0]?.location.source!;
  assert.equal(loc.startLine, 10);
  assert.equal(loc.startCol, 4);
  assert.equal(loc.endLine, 10);
  assert.equal(loc.endCol, 20);
});

test('location from line fallback when textRange absent', () => {
  const out = normalize(doc([issue({ line: 17 })]), CTX, NO_SOURCES);
  const loc = out.candidates[0]?.location.source!;
  assert.equal(loc.startLine, 17);
  assert.equal(loc.startCol, 0);
  assert.equal(loc.endLine, 17);
  assert.equal(loc.endCol, 0);
});

test('no location when neither textRange nor line is present', () => {
  const out = normalize(doc([issue()]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.location.source, undefined);
});

test('evidence is empty object', () => {
  const out = normalize(doc([issue()]), CTX, NO_SOURCES);
  assert.deepEqual(out.candidates[0]?.evidence, {});
});

test('unmapped severity yields unmapped_severity diagnostic', () => {
  const out = normalize(doc([issue({ impacts: [{ softwareQuality: 'SECURITY', severity: 'EXTREME' }] })]), CTX, NO_SOURCES);
  assert.equal(out.candidates[0]?.severity, 'unknown');
  assert.ok(out.diagnostics.some((d) => d.code === 'unmapped_severity'));
});

test('empty issues list: complete, zero candidates', () => {
  const out = normalize(doc([]), CTX, NO_SOURCES);
  assert.equal(out.completeness, 'complete');
  assert.equal(out.candidates.length, 0);
  assert.equal(out.unusableCount, 0);
});

test('invalid document shape: failed, malformed_report', () => {
  const out = normalize({ site: [] } as JsonValue, CTX, NO_SOURCES);
  assert.equal(out.completeness, 'failed');
  assert.deepEqual(out.candidates, []);
  assert.ok(out.diagnostics.some((d) => d.code === 'malformed_report'));
});

test('unusable issues increment count and partial completeness', () => {
  const out = normalize(doc([issue(), { key: 'BAD' }]), CTX, NO_SOURCES);
  assert.equal(out.completeness, 'partial');
  assert.equal(out.candidates.length, 1);
  assert.equal(out.unusableCount, 1);
});

test('coverageLoss propagates and marks partial', () => {
  const loss: RawDiagnostic = { code: 'resource_limit_exceeded', level: 'warn', tool: 'sonarqube', message: 'truncated' };
  const out = normalize(doc([issue()]), { ...CTX, coverageLoss: [loss] }, NO_SOURCES);
  assert.equal(out.completeness, 'partial');
  assert.deepEqual(out.coverageLoss, [loss]);
});

test('severityMappingVersion is sonarqube-1', () => {
  const out = normalize(doc([]), CTX, NO_SOURCES);
  assert.equal(out.severityMappingVersion, 'sonarqube-1');
});

test('producerVersion is carried through', () => {
  const out = normalize(doc([]), { ...CTX, producerVersion: '10.6.0' }, NO_SOURCES);
  assert.equal(out.producerVersion, '10.6.0');
});

test('redactionsApplied tracks pointer matches', () => {
  const touched = new Set(['/issues/0/message']);
  const out = normalize(doc([issue(), issue({ key: 'K2' })]), { ...CTX, redactionTouched: touched }, NO_SOURCES);
  assert.equal(out.candidates[0]?.redactionsApplied, true);
  assert.equal(out.candidates[1]?.redactionsApplied, false);
});
