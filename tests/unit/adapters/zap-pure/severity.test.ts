import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { JsonValue, Severity } from '../../../../src/contracts/enums.js';
import { mapSeverity } from '../../../../src/adapters/zap/severity.js';

// zap-1 is exact and case-sensitive. [verify] V3: strings on real ZAP.
const MAPPED: [string, Severity][] = [
  ['Informational', 'info'],
  ['Low', 'low'],
  ['Medium', 'medium'],
  ['High', 'high'],
];

const UNMAPPED: [string, JsonValue | undefined][] = [
  ['lowercase informational', 'informational'],
  ['uppercase LOW', 'LOW'],
  ['lowercase medium', 'medium'],
  ['leading space', ' High'],
  ['trailing space', 'High '],
  ['Critical is not in zap-1', 'Critical'],
  ['Warning is not in zap-1', 'Warning'],
  ['empty string', ''],
  ['numeric risk code', '0'],
  ['numeric value', 2],
  ['boolean', true],
  ['array', ['High']],
  ['null', null],
  ['missing', undefined],
];

for (const [text, severity] of MAPPED) {
  test(`${text} maps to ${severity}`, () => {
    assert.equal(mapSeverity(text), severity);
  });
}

for (const [label, value] of UNMAPPED) {
  test(`${label} maps to unknown`, () => {
    assert.equal(mapSeverity(value), 'unknown');
  });
}
