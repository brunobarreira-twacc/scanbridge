// Declared field order for every object type in OBJECT_TYPES (spec 02). Object key order in
// this table is the serialized key order; each entry also says how its value is ordered.
// A test asserts each table covers exactly the keys of the matching Zod object.

export type Rule =
  | { kind: 'scalar' }
  | { kind: 'object'; type: string }
  | { kind: 'union'; by: string; members: Record<string, string> }
  | { kind: 'items'; type: string; sort?: 'fingerprint' | 'occurrence' }
  | { kind: 'strings'; order: 'ordered' | 'set' | 'multiset' }
  | { kind: 'counts' };

export type Layout = Record<string, Rule>;

const S = { kind: 'scalar' } as const;
const COUNTS = { kind: 'counts' } as const;
const obj = (type: string): Rule => ({ kind: 'object', type });
const items = (type: string, sort?: 'fingerprint' | 'occurrence'): Rule => ({ kind: 'items', type, sort });
const strings = (order: 'ordered' | 'set' | 'multiset'): Rule => ({ kind: 'strings', order });
const union = (by: string, members: Record<string, string>): Rule => ({ kind: 'union', by, members });

export const LAYOUT: Record<string, Layout> = {
  TextField: {
    text: S,
    truncated: S,
    original_length: S,
  },
  DiagnosticDetail: {
    text: S,
    truncated: S,
    original_length: S,
    untrusted: S,
  },
  Diagnostic: {
    code: S,
    level: S,
    tool: S,
    message: S,
    detail: obj('DiagnosticDetail'),
  },
  GitTarget: {
    kind: S,
    relative_path: S,
    revision: S,
    dirty: S,
    content_digest: S,
  },
  DirectoryTarget: {
    kind: S,
    relative_path: S,
    content_digest: S,
  },
  HttpOriginTarget: {
    kind: S,
    origin: S,
    asserted_revision: S,
  },
  SourceLocation: {
    path: S,
    start_line: S,
    start_col: S,
    end_line: S,
    end_col: S,
  },
  RuntimeLocation: {
    url: S,
    method: S,
    param: S,
  },
  Evidence: {
    snippet: obj('TextField'),
    attack: obj('TextField'),
    evidence: obj('TextField'),
    message_id: S,
  },
  Occurrence: {
    severity: S,
    severity_original: S,
    source_location: obj('SourceLocation'),
    runtime_location: obj('RuntimeLocation'),
    evidence: obj('Evidence'),
  },
  Finding: {
    fingerprint: S,
    fingerprint_quality: S,
    producer_fingerprint: S,
    rule_id: S,
    producer_reference: S,
    title: obj('TextField'),
    description: obj('TextField'),
    severity: S,
    severity_original: S,
    severity_complete: S,
    confidence: obj('TextField'),
    category: S,
    references: strings('set'),
    status: S,
    redactions_applied: S,
    occurrence_count: S,
    occurrences: items('Occurrence', 'occurrence'),
  },
  NormalizedDocument: {
    schema_version: S,
    content_trust: S,
    producer: S,
    producer_version: S,
    target: union('kind', {
      git: 'GitTarget',
      directory: 'DirectoryTarget',
      http_origin: 'HttpOriginTarget',
    }),
    completeness: S,
    authoritative: S,
    non_authoritative_reasons: strings('set'),
    fingerprint_version: S,
    severity_mapping_version: S,
    redaction_policy_version: S,
    rules_digest: S,
    configuration_digest: S,
    raw_sha256_before_redaction: S,
    raw_sha256_after_redaction: S,
    redaction_summary: COUNTS,
    findings: items('Finding', 'fingerprint'),
  },
  Exclusion: {
    path: S,
    reason: S,
  },
  Artifacts: {
    directory: S,
    raw: strings('ordered'),
    normalized: S,
  },
  ScanResult: {
    schema_version: S,
    command: S,
    status: S,
    exit_code: S,
    scan_id: S,
    adapter: S,
    started_at: S,
    finished_at: S,
    duration_ms: S,
    authoritative: S,
    non_authoritative_reasons: strings('set'),
    findings_count: S,
    exclusions: items('Exclusion'),
    diagnostics: items('Diagnostic'),
    artifacts: obj('Artifacts'),
  },
  ErrorBody: {
    code: S,
    message: S,
  },
  ErrorEnvelope: {
    schema_version: S,
    status: S,
    error: obj('ErrorBody'),
  },
  Problem: {
    code: S,
    message: S,
  },
  DoctorTool: {
    name: S,
    status: S,
    version: S,
    api_key: S,
    api_key_verified: S,
    problems: items('Problem'),
  },
  DoctorResult: {
    schema_version: S,
    command: S,
    ok: S,
    tools: items('DoctorTool'),
  },
  FindingReference: {
    rule_id: S,
    producer_reference: S,
    title: obj('TextField'),
    fingerprint_quality: S,
    severity: S,
    severity_original: S,
    severity_complete: S,
    confidence: obj('TextField'),
    occurrence_count: S,
    // A sorted multiset: one entry per occurrence, so duplicates are kept.
    occurrence_severities: strings('multiset'),
  },
  CompareFinding: {
    fingerprint: S,
    state: S,
    severity_comparison: S,
    changed_fields: strings('set'),
    base: obj('FindingReference'),
    head: obj('FindingReference'),
  },
  AssertedRevision: {
    value: S,
    asserted: S,
  },
  CompareInput: {
    producer_version: S,
    completeness: S,
    authoritative: S,
    non_authoritative_reasons: strings('set'),
    asserted_revision: obj('AssertedRevision'),
  },
  CompareSummary: {
    new: S,
    resolved: S,
    unchanged: S,
    changed: S,
    severity_increased: S,
    severity_decreased: S,
    incomparable: S,
    severity_comparison_incomparable: S,
  },
  CompareMetadata: {
    configuration_digest_equal: S,
  },
  CompareResult: {
    command: S,
    authoritative: S,
    non_authoritative_reasons: strings('set'),
    base: obj('CompareInput'),
    head: obj('CompareInput'),
    summary: obj('CompareSummary'),
    findings: items('CompareFinding', 'fingerprint'),
    metadata: obj('CompareMetadata'),
  },
};

/** The declared key order of one object type. */
export const FIELD_ORDER = Object.fromEntries(
  Object.entries(LAYOUT).map(([type, layout]) => [type, Object.keys(layout)]),
) as Record<string, readonly string[]>;
