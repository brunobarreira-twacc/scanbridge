import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  BUILTIN_REDACTION_VERSION,
  COMPARE_REASONS,
  COMPARE_STATES,
  COMPLETENESS,
  DIAGNOSTIC_CODES,
  ERROR_CODES,
  EXIT_CODES,
  FINGERPRINT_QUALITIES,
  FINGERPRINT_VERSION,
  SCAN_REASONS,
  SCHEMA_VERSION,
  SEMGREP_MAPPING_VERSION,
  SEVERITIES,
  SEVERITY_RANK,
  ZAP_MAPPING_VERSION,
} from '../../../src/contracts/enums.js';

test('diagnostic codes: 20, exact members', () => {
  assert.equal(DIAGNOSTIC_CODES.length, 20);
  assert.equal(new Set(DIAGNOSTIC_CODES).size, 20);
  assert.deepEqual(
    [...DIAGNOSTIC_CODES].sort(),
    [
      'tool_unavailable', 'tool_execution_failed', 'tool_timeout', 'partial_coverage', 'resource_limit_exceeded',
      'unmapped_error_type', 'unmapped_severity', 'non_deterministic_rules', 'out_of_scope_target', 'redaction_failed',
      'malformed_report', 'target_identity_unavailable', 'target_changed_during_scan', 'fingerprint_degraded',
      'no_files_scanned', 'no_urls_discovered', 'zap_session_not_clean', 'zap_unreachable_or_rejected', 'bad_api_key',
      'target_url_overridden',
    ].sort(),
  );
});

test('scan reasons: 6, exact members', () => {
  assert.deepEqual([...SCAN_REASONS], [
    'partial_scan', 'registry_rules', 'auto_rules', 'fingerprint_degraded', 'unmapped_severity', 'offline_report',
  ]);
});

test('compare reasons: 10, exact members', () => {
  assert.equal(COMPARE_REASONS.length, 10);
  assert.deepEqual([...COMPARE_REASONS].sort(), [
    'partial_input_allowed', 'fingerprint_version_mismatch', 'severity_mapping_version_mismatch',
    'redaction_policy_mismatch', 'rules_mismatch', 'producer_version_mismatch', 'producer_version_incomparable',
    'target_identity_incomparable', 'base_input_non_authoritative', 'head_input_non_authoritative',
  ].sort());
});

test('completeness, severities, ranks, quality, states, error codes', () => {
  assert.deepEqual([...COMPLETENESS], ['complete', 'partial', 'unverified', 'failed']);
  assert.deepEqual([...SEVERITIES], ['info', 'low', 'medium', 'high', 'critical', 'unknown']);
  assert.deepEqual({ ...SEVERITY_RANK }, { info: 0, low: 1, medium: 2, high: 3, critical: 4 });
  assert.equal('unknown' in SEVERITY_RANK, false);
  assert.deepEqual([...FINGERPRINT_QUALITIES], ['exact', 'degraded']);
  assert.deepEqual([...COMPARE_STATES], [
    'new', 'resolved', 'unchanged', 'changed', 'severity_increased', 'severity_decreased', 'incomparable',
  ]);
  assert.deepEqual([...ERROR_CODES], [
    'usage_error', 'invalid_configuration', 'partial_input_refused', 'invalid_report', 'incompatible_reports',
  ]);
});

test('exit codes 0-5 and versions', () => {
  assert.deepEqual(Object.values(EXIT_CODES), [0, 1, 2, 3, 4, 5]);
  assert.equal(SCHEMA_VERSION, '1');
  assert.equal(FINGERPRINT_VERSION, 'v1');
  assert.equal(SEMGREP_MAPPING_VERSION, 'semgrep-1');
  assert.equal(ZAP_MAPPING_VERSION, 'zap-1');
  assert.equal(BUILTIN_REDACTION_VERSION, '1');
});
