import type {
  Finding,
  NormalizedDocument,
  Occurrence,
  Target,
  TextField,
} from '../../../src/schemas/index.js';

export const DIGEST_RULES = 'a'.repeat(64);
export const DIGEST_CONFIG = 'b'.repeat(64);
export const DIGEST_RAW = 'c'.repeat(64);
export const DIGEST_CONTENT = 'd'.repeat(64);
export const DIGEST_CONTENT_OTHER = 'e'.repeat(64);

/** A valid `v1:` fingerprint; the number is hex-encoded so the output is stable and sortable. */
export function fp(n: number): string {
  return `v1:${n.toString(16).padStart(64, '0')}`;
}

export function text(value: string): TextField {
  return { text: value, truncated: false, original_length: [...value].length };
}

export function gitTarget(overrides: Partial<Extract<Target, { kind: 'git' }>> = {}): Target {
  return {
    kind: 'git',
    relative_path: 'services/api',
    revision: 'rev-1',
    dirty: false,
    content_digest: DIGEST_CONTENT,
    ...overrides,
  };
}

export function directoryTarget(overrides: Partial<Extract<Target, { kind: 'directory' }>> = {}): Target {
  return {
    kind: 'directory',
    relative_path: 'services/api',
    content_digest: DIGEST_CONTENT,
    ...overrides,
  };
}

export function httpOriginTarget(overrides: Partial<Extract<Target, { kind: 'http_origin' }>> = {}): Target {
  return { kind: 'http_origin', origin: 'http://127.0.0.1:8080', ...overrides };
}

export function occurrence(overrides: Partial<Occurrence> = {}): Occurrence {
  return {
    severity: 'high',
    severity_original: 'ERROR',
    evidence: { snippet: text('db.query(id)') },
    ...overrides,
  };
}

/** Occurrence count follows the occurrences unless overridden. */
export function finding(n: number, overrides: Partial<Finding> = {}): Finding {
  const occurrences = overrides.occurrences ?? [occurrence()];
  return {
    fingerprint: fp(n),
    fingerprint_quality: 'exact',
    rule_id: 'rules.sql-injection',
    producer_reference: null,
    title: text('SQL injection'),
    severity: 'high',
    severity_original: 'ERROR',
    severity_complete: true,
    confidence: null,
    status: 'open',
    occurrence_count: occurrences.length,
    ...overrides,
    occurrences,
  };
}

/** Semgrep-style complete, authoritative document with a git target by default. */
export function document(overrides: Partial<NormalizedDocument> = {}): NormalizedDocument {
  return {
    schema_version: '1',
    content_trust: 'untrusted_producer_content',
    producer: 'semgrep',
    producer_version: '1.50.0',
    target: gitTarget(),
    completeness: 'complete',
    authoritative: true,
    non_authoritative_reasons: [],
    fingerprint_version: 'v1',
    severity_mapping_version: 'semgrep-1',
    redaction_policy_version: '1',
    rules_digest: DIGEST_RULES,
    configuration_digest: DIGEST_CONFIG,
    raw_sha256_before_redaction: DIGEST_RAW,
    raw_sha256_after_redaction: DIGEST_RAW,
    redaction_summary: {},
    findings: [],
    ...overrides,
  };
}

/** Live ZAP document: complete, authoritative, rules digest null, optional asserted revision. */
export function zapDocument(overrides: Partial<NormalizedDocument> = {}): NormalizedDocument {
  return document({
    producer: 'zap',
    producer_version: '2.15.0',
    target: httpOriginTarget(),
    severity_mapping_version: 'zap-1',
    rules_digest: null,
    ...overrides,
  });
}
