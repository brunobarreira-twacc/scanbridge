import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TEXT_FIELD_MAX } from '../../../src/contracts/limits.js';
import { finalizeDiagnostics } from '../../../src/core/findings/index.js';

test('message passes through unchanged and the schema shape is kept', () => {
  const [diagnostic] = finalizeDiagnostics([{ code: 'partial_coverage', level: 'warn', tool: 'semgrep', message: 'Scanbridge text\u0001' }]);
  assert.deepEqual(diagnostic, { code: 'partial_coverage', level: 'warn', tool: 'semgrep', message: 'Scanbridge text\u0001' });
});

test('detail becomes sanitized, truncated, untrusted structured text', () => {
  const detail = `\u0007${'d'.repeat(TEXT_FIELD_MAX)}`;
  const [diagnostic] = finalizeDiagnostics([{ code: 'tool_execution_failed', level: 'error', message: 'failed', detail }]);
  assert.deepEqual(diagnostic?.detail, {
    text: `�${'d'.repeat(TEXT_FIELD_MAX - 1)}`,
    truncated: true,
    original_length: TEXT_FIELD_MAX + 1,
    untrusted: true,
  });
});

test('a tool outside the producer enum is omitted rather than emitted invalid', () => {
  const [diagnostic] = finalizeDiagnostics([{ code: 'target_identity_unavailable', level: 'warn', tool: 'git', message: 'no identity' }]);
  assert.equal('tool' in (diagnostic ?? {}), false);
});

test('a diagnostic without tool or detail has neither key', () => {
  const [diagnostic] = finalizeDiagnostics([{ code: 'no_files_scanned', level: 'warn', message: 'none' }]);
  assert.deepEqual(diagnostic, { code: 'no_files_scanned', level: 'warn', message: 'none' });
});
