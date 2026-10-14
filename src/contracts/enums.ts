export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export const DIAGNOSTIC_CODES = [
  'tool_unavailable',
  'tool_execution_failed',
  'tool_timeout',
  'partial_coverage',
  'resource_limit_exceeded',
  'unmapped_error_type',
  'unmapped_severity',
  'non_deterministic_rules',
  'out_of_scope_target',
  'redaction_failed',
  'malformed_report',
  'target_identity_unavailable',
  'target_changed_during_scan',
  'fingerprint_degraded',
  'no_files_scanned',
  'no_urls_discovered',
  'zap_session_not_clean',
  'zap_unreachable_or_rejected',
  'bad_api_key',
  'target_url_overridden',
] as const;
export type DiagnosticCode = (typeof DIAGNOSTIC_CODES)[number];

export const SCAN_REASONS = [
  'partial_scan',
  'registry_rules',
  'auto_rules',
  'fingerprint_degraded',
  'unmapped_severity',
  'offline_report',
] as const;
export type ScanReason = (typeof SCAN_REASONS)[number];

export const COMPARE_REASONS = [
  'partial_input_allowed',
  'fingerprint_version_mismatch',
  'severity_mapping_version_mismatch',
  'redaction_policy_mismatch',
  'rules_mismatch',
  'producer_version_mismatch',
  'producer_version_incomparable',
  'target_identity_incomparable',
  'base_input_non_authoritative',
  'head_input_non_authoritative',
] as const;
export type CompareReason = (typeof COMPARE_REASONS)[number];

export const COMPLETENESS = ['complete', 'partial', 'unverified', 'failed'] as const;
export type Completeness = (typeof COMPLETENESS)[number];

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical', 'unknown'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** `unknown` has no rank. */
export const SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const satisfies Record<Exclude<Severity, 'unknown'>, number>;

export const FINGERPRINT_QUALITIES = ['exact', 'degraded'] as const;
export type FingerprintQuality = (typeof FINGERPRINT_QUALITIES)[number];

export const COMPARE_STATES = [
  'new',
  'resolved',
  'unchanged',
  'changed',
  'severity_increased',
  'severity_decreased',
  'incomparable',
] as const;
export type CompareState = (typeof COMPARE_STATES)[number];

export const ERROR_CODES = [
  'usage_error',
  'invalid_configuration',
  'partial_input_refused',
  'invalid_report',
  'incompatible_reports',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export const EXIT_CODES = {
  OK: 0,
  USAGE_OR_CONFIG: 1,
  TOOL_UNAVAILABLE: 2,
  SCAN_FAILED: 3,
  PARTIAL: 4,
  INVALID_OR_INCOMPATIBLE_REPORT: 5,
} as const;
export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export const SCHEMA_VERSION = '1';
export const FINGERPRINT_VERSION = 'v1';
export const SEMGREP_MAPPING_VERSION = 'semgrep-1';
export const ZAP_MAPPING_VERSION = 'zap-1';
export const BUILTIN_REDACTION_VERSION = '1';
