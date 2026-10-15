import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SNIPPET_FIELD_MAX, TEXT_FIELD_MAX } from '../../../src/contracts/limits.js';
import { plainText, sanitizeText, textField } from '../../../src/core/findings/text.js';
import { buildSemgrep, semgrepCandidate, zapCandidate, buildZap } from './helpers.js';

const REPLACED = [0x00, 0x01, 0x08, 0x0b, 0x0c, 0x0e, 0x1b, 0x1f, 0x7f];
const KEPT = [0x09, 0x0a, 0x0d, 0x20, 0x7e, 0x80];

test('the control characters in spec 04 become U+FFFD; tab, LF and CR are kept', () => {
  for (const code of REPLACED) {
    assert.equal(sanitizeText(`a${String.fromCodePoint(code)}b`), 'a�b', `U+${code.toString(16)}`);
  }
  for (const code of KEPT) {
    const ch = String.fromCodePoint(code);
    assert.equal(sanitizeText(ch), ch, `U+${code.toString(16)} is unchanged`);
  }
});

test('sanitization does not change the code-point count', () => {
  const value = '\u0001\u0002😀\u007f';
  assert.equal([...sanitizeText(value)].length, [...value].length);
});

test('truncation counts code points and keeps an astral character whole at the cut', () => {
  const value = `${'a'.repeat(TEXT_FIELD_MAX - 1)}😀bcd`;
  const field = textField(value, TEXT_FIELD_MAX);
  assert.equal(field.truncated, true);
  assert.equal(field.text, `${'a'.repeat(TEXT_FIELD_MAX - 1)}😀`);
  assert.equal([...field.text].length, TEXT_FIELD_MAX);
  assert.equal(field.original_length, TEXT_FIELD_MAX + 3);
});

test('original_length counts code points, not UTF-16 units', () => {
  assert.deepEqual(textField('😀😀', TEXT_FIELD_MAX), { text: '😀😀', truncated: false, original_length: 2 });
});

test('text at exactly the limit is not truncated', () => {
  const value = 'x'.repeat(SNIPPET_FIELD_MAX);
  assert.deepEqual(textField(value, SNIPPET_FIELD_MAX), { text: value, truncated: false, original_length: SNIPPET_FIELD_MAX });
});

test('title, description and confidence are structured; severity_original, category and message_id stay plain', () => {
  const [finding] = buildZap([zapCandidate({ severityOriginal: 'Med\u0001ium', category: 'web\u0002', evidence: { attack: null, evidence: null, message_id: '1\u00177' } })]).findings;
  assert.equal(typeof finding?.title, 'object');
  assert.equal(typeof finding?.confidence, 'object');
  assert.equal(finding?.severity_original, 'Med�ium');
  assert.equal(finding?.category, 'web�');
  assert.equal(finding?.occurrences[0]?.severity_original, 'Med�ium');
  assert.equal(finding?.occurrences[0]?.evidence.message_id, '1�7');
});

test('a snippet is structured, sanitized and truncated at the snippet limit', () => {
  const text = `\u0001${'s'.repeat(SNIPPET_FIELD_MAX)}`;
  const [finding] = buildSemgrep([semgrepCandidate({ snippet: { ok: true, text } })]).findings;
  const snippet = finding?.occurrences[0]?.evidence.snippet;
  assert.equal(snippet?.truncated, true);
  assert.equal(snippet?.original_length, SNIPPET_FIELD_MAX + 1);
  assert.equal(snippet?.text.startsWith('�'), true);
  assert.equal([...(snippet?.text ?? '')].length, SNIPPET_FIELD_MAX);
});

test('the title and description are truncated at the text limit and the description is omitted when null', () => {
  const [finding] = buildSemgrep([semgrepCandidate({ title: 't'.repeat(TEXT_FIELD_MAX + 5), description: null })]).findings;
  assert.equal(finding?.title.truncated, true);
  assert.equal(finding?.title.original_length, TEXT_FIELD_MAX + 5);
  assert.equal(finding?.description, undefined);
});

test('plainText sanitizes without structure or truncation', () => {
  const long = 'z'.repeat(TEXT_FIELD_MAX + 10);
  assert.equal(plainText(long), long);
  assert.equal(plainText('\u0000x'), '�x');
});

test('evidence keys outside the schema (Semgrep producer_lines) are dropped', () => {
  const [finding] = buildSemgrep([semgrepCandidate()]).findings;
  assert.equal(Object.keys(finding?.occurrences[0]?.evidence ?? {}).includes('producer_lines'), false);
});
