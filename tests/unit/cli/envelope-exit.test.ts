import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { compareEnvelope, doctorEnvelope, errorEnvelope } from '../../../src/cli/envelope.js';
import { doctorExitCode, ERROR_EXIT_CODES } from '../../../src/cli/exit.js';
import { compareDocuments } from '../../../src/core/comparison/index.js';
import { document } from '../comparison/fixtures.js';

describe('error envelope', () => {
  it('is exactly one JSON document with a trailing newline', () => {
    const text = errorEnvelope('usage_error', 'scan requires --output');
    assert.ok(text.endsWith('\n'));
    // JSON.parse rejects a second document, so a successful parse proves there is exactly one.
    assert.deepEqual(JSON.parse(text), {
      schema_version: '1',
      status: 'error',
      error: { code: 'usage_error', message: 'scan requires --output' },
    });
  });
});

describe('doctor envelope', () => {
  it('keeps spec 03 field names and carries only api_key presence', () => {
    const text = doctorEnvelope({
      schema_version: '1',
      command: 'doctor',
      ok: false,
      tools: [
        { name: 'semgrep', status: 'ready', version: '1.2.3', problems: [] },
        {
          name: 'zap',
          status: 'unavailable',
          version: null,
          api_key: 'missing',
          api_key_verified: false,
          problems: [{ code: 'tool_unavailable', message: 'SCANBRIDGE_ZAP_API_KEY is not set' }],
        },
      ],
    });
    assert.ok(text.endsWith('\n'));
    const parsed = JSON.parse(text);
    assert.equal(parsed.command, 'doctor');
    assert.equal(parsed.tools[1].api_key, 'missing');
    assert.equal(parsed.tools[1].api_key_verified, false);
  });
});

describe('compare envelope', () => {
  it('serializes a comparison result as one JSON document', () => {
    const outcome = compareDocuments(document(), document(), { allowPartial: false });
    assert.equal(outcome.ok, true);
    if (!outcome.ok) return;
    const text = compareEnvelope(outcome.result);
    assert.ok(text.endsWith('\n'));
    assert.equal(JSON.parse(text).command, 'compare');
  });
});

describe('exit codes', () => {
  it('maps every error code to the spec 03 exit code', () => {
    assert.deepEqual(ERROR_EXIT_CODES, {
      usage_error: 1,
      invalid_configuration: 1,
      partial_input_refused: 4,
      invalid_report: 5,
      incompatible_reports: 5,
    });
  });

  it('maps doctor readiness to 0 or 2', () => {
    assert.equal(doctorExitCode(true), 0);
    assert.equal(doctorExitCode(false), 2);
  });
});
