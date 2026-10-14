import { createHash } from 'node:crypto';

export interface CorpusEntry {
  label: string;
  doc: unknown;
  valid: boolean;
}

export const digest = (seed: string): string => createHash('sha256').update(seed).digest('hex');

const text = (value: string) => ({ text: value, truncated: false, original_length: [...value].length });

/** Returns a deep copy of `base` with `change` applied. */
const variant = <T>(base: T, change: (draft: any) => void): unknown => {
  const draft = structuredClone(base);
  change(draft);
  return draft;
};

const semgrepOccurrence = {
  severity: 'high',
  severity_original: 'ERROR',
  source_location: { path: 'src/db.ts', start_line: 42, start_col: 3, end_line: 42, end_col: 58 },
  evidence: { snippet: text('db.query("SELECT * FROM t WHERE id=" + id)') },
};

const semgrepFinding = {
  fingerprint: `v1:${digest('finding-semgrep')}`,
  fingerprint_quality: 'exact',
  rule_id: 'rules.sql-injection',
  producer_reference: null,
  title: text('rules.sql-injection'),
  description: text('User input reaches a SQL query.'),
  severity: 'high',
  severity_original: 'ERROR',
  severity_complete: true,
  confidence: null,
  category: null,
  references: [],
  status: 'open',
  redactions_applied: false,
  occurrence_count: 1,
  occurrences: [semgrepOccurrence],
};

const zapFinding = {
  fingerprint: `v1:${digest('finding-zap')}`,
  fingerprint_quality: 'exact',
  rule_id: '10202',
  producer_reference: '10202',
  title: text('Absence of Anti-CSRF Tokens'),
  severity: 'medium',
  severity_original: 'Medium',
  severity_complete: true,
  confidence: text('Low'),
  status: 'open',
  occurrence_count: 1,
  occurrences: [
    {
      severity: 'medium',
      severity_original: 'Medium',
      runtime_location: { url: 'http://127.0.0.1:8080/login', method: 'POST', param: '' },
      evidence: { attack: null, evidence: text('<form action="/login">'), message_id: '17' },
    },
  ],
};

const baseNormalized = {
  schema_version: '1',
  content_trust: 'untrusted_producer_content',
  producer: 'semgrep',
  producer_version: '1.100.0',
  target: {
    kind: 'git',
    relative_path: 'app',
    revision: 'abc123',
    dirty: false,
    content_digest: digest('tree'),
  },
  completeness: 'complete',
  authoritative: true,
  non_authoritative_reasons: [],
  fingerprint_version: 'v1',
  severity_mapping_version: 'semgrep-1',
  redaction_policy_version: '1',
  rules_digest: digest('rules'),
  configuration_digest: digest('config'),
  raw_sha256_before_redaction: digest('raw-before'),
  raw_sha256_after_redaction: digest('raw-after'),
  redaction_summary: {},
  findings: [] as unknown[],
};

export const normalizedCorpus: CorpusEntry[] = [
  { label: 'valid: git target, no findings', doc: baseNormalized, valid: true },
  {
    label: 'valid: semgrep finding with a source occurrence',
    doc: variant(baseNormalized, (d) => {
      d.findings = [semgrepFinding];
      d.redaction_summary = { 'rules.secret': 2 };
    }),
    valid: true,
  },
  {
    label: 'valid: directory target, null digest, partial and non-authoritative',
    doc: variant(baseNormalized, (d) => {
      d.target = { kind: 'directory', relative_path: 'app', content_digest: null };
      d.completeness = 'partial';
      d.authoritative = false;
      d.non_authoritative_reasons = ['partial_scan'];
      d.rules_digest = null;
    }),
    valid: true,
  },
  {
    label: 'valid: zap finding on http_origin with asserted revision',
    doc: variant(baseNormalized, (d) => {
      d.producer = 'zap';
      d.producer_version = null;
      d.target = { kind: 'http_origin', origin: 'http://127.0.0.1:8080', asserted_revision: 'v2.1' };
      d.completeness = 'unverified';
      d.authoritative = false;
      d.non_authoritative_reasons = ['offline_report'];
      d.fingerprint_version = 'v1';
      d.severity_mapping_version = 'zap-1';
      d.rules_digest = null;
      d.findings = [zapFinding];
    }),
    valid: true,
  },
  {
    label: 'valid: two occurrences with different original severities',
    doc: variant(baseNormalized, (d) => {
      const second = { ...semgrepOccurrence, severity: 'low', severity_original: 'INFO' };
      d.findings = [
        {
          ...structuredClone(semgrepFinding),
          occurrence_count: 2,
          occurrences: [structuredClone(semgrepOccurrence), second],
        },
      ];
    }),
    valid: true,
  },
  { label: 'invalid: unknown top-level key', doc: variant(baseNormalized, (d) => (d.extra = 1)), valid: false },
  { label: 'invalid: wrong completeness value', doc: variant(baseNormalized, (d) => (d.completeness = 'Complete')), valid: false },
  {
    label: 'invalid: float occurrence_count',
    doc: variant(baseNormalized, (d) => {
      d.findings = [{ ...structuredClone(semgrepFinding), occurrence_count: 1.5 }];
    }),
    valid: false,
  },
  { label: 'invalid: wrong content_trust literal', doc: variant(baseNormalized, (d) => (d.content_trust = 'trusted')), valid: false },
  { label: 'invalid: missing schema_version', doc: variant(baseNormalized, (d) => delete d.schema_version), valid: false },
  { label: 'invalid: target kind not in the union', doc: variant(baseNormalized, (d) => (d.target = { kind: 'svn', relative_path: 'app' })), valid: false },
  {
    label: 'invalid: git target missing dirty',
    doc: variant(baseNormalized, (d) => {
      d.target = { kind: 'git', relative_path: 'app', revision: null, content_digest: null };
    }),
    valid: false,
  },
  {
    label: 'invalid: finding status not open',
    doc: variant(baseNormalized, (d) => {
      d.findings = [{ ...structuredClone(semgrepFinding), status: 'closed' }];
    }),
    valid: false,
  },
  {
    label: 'invalid: unknown key inside a text field',
    doc: variant(baseNormalized, (d) => {
      d.findings = [{ ...structuredClone(semgrepFinding), title: { ...text('x'), extra: true } }];
    }),
    valid: false,
  },
  {
    label: 'invalid: unknown key inside a source location (inferred is reserved, not emitted)',
    doc: variant(baseNormalized, (d) => {
      d.findings = [
        {
          ...structuredClone(semgrepFinding),
          occurrences: [{ ...semgrepOccurrence, source_location: { ...semgrepOccurrence.source_location, inferred: true } }],
        },
      ];
    }),
    valid: false,
  },
  {
    label: 'invalid: malformed fingerprint',
    doc: variant(baseNormalized, (d) => {
      d.findings = [{ ...structuredClone(semgrepFinding), fingerprint: 'v1:abc' }];
    }),
    valid: false,
  },
];

const baseScanResult = {
  schema_version: '1',
  command: 'scan',
  status: 'complete',
  exit_code: 0,
  scan_id: '20261013T142501.123Z-3fa9c0d1',
  adapter: 'semgrep',
  started_at: '2026-10-13T14:25:01.123Z',
  finished_at: '2026-10-13T14:25:09.246Z',
  duration_ms: 8123,
  authoritative: true,
  non_authoritative_reasons: [],
  findings_count: 0,
  exclusions: [],
  diagnostics: [],
  artifacts: { directory: '/out/20261013T142501.123Z-3fa9c0d1', raw: ['raw/semgrep.json'], normalized: 'normalized.json' },
};

export const scanResultCorpus: CorpusEntry[] = [
  { label: 'valid: complete scan', doc: baseScanResult, valid: true },
  {
    label: 'valid: partial scan with exit 4 and an untrusted diagnostic detail',
    doc: variant(baseScanResult, (d) => {
      d.status = 'partial';
      d.exit_code = 4;
      d.authoritative = false;
      d.non_authoritative_reasons = ['partial_scan'];
      d.diagnostics = [
        {
          code: 'partial_coverage',
          level: 'warn',
          tool: 'semgrep',
          message: 'Some files were not fully analyzed.',
          detail: { ...text('detail'), untrusted: true },
        },
      ];
    }),
    valid: true,
  },
  {
    label: 'valid: failed scan with null artifacts and an exclusion',
    doc: variant(baseScanResult, (d) => {
      d.status = 'failed';
      d.exit_code = 3;
      d.authoritative = false;
      d.exclusions = [{ path: 'out', reason: 'output_directory' }];
      d.artifacts = { directory: null, raw: null, normalized: null };
    }),
    valid: true,
  },
  {
    label: 'valid: unverified zap scan with exit 0',
    doc: variant(baseScanResult, (d) => {
      d.adapter = 'zap';
      d.status = 'unverified';
      d.authoritative = false;
      d.non_authoritative_reasons = ['offline_report'];
      d.artifacts = { directory: null, raw: null, normalized: 'normalized.json' };
    }),
    valid: true,
  },
  {
    label: 'valid: scan with a tool_unavailable diagnostic and exit 2',
    doc: variant(baseScanResult, (d) => {
      d.status = 'failed';
      d.exit_code = 2;
      d.diagnostics = [{ code: 'tool_unavailable', level: 'error', tool: 'semgrep', message: 'semgrep not found' }];
    }),
    valid: true,
  },
  { label: 'invalid: unknown top-level key', doc: variant(baseScanResult, (d) => (d.extra = 'x')), valid: false },
  { label: 'invalid: exit code 1 is not a scan envelope', doc: variant(baseScanResult, (d) => (d.exit_code = 1)), valid: false },
  { label: 'invalid: float duration_ms', doc: variant(baseScanResult, (d) => (d.duration_ms = 8.5)), valid: false },
  { label: 'invalid: wrong status value', doc: variant(baseScanResult, (d) => (d.status = 'ok')), valid: false },
  { label: 'invalid: missing scan_id', doc: variant(baseScanResult, (d) => delete d.scan_id), valid: false },
  { label: 'invalid: wrong command literal', doc: variant(baseScanResult, (d) => (d.command = 'compare')), valid: false },
  { label: 'invalid: unknown adapter', doc: variant(baseScanResult, (d) => (d.adapter = 'bandit')), valid: false },
  {
    label: 'invalid: diagnostic detail not marked untrusted',
    doc: variant(baseScanResult, (d) => {
      d.diagnostics = [
        { code: 'malformed_report', level: 'warn', message: 'm', detail: { ...text('x'), untrusted: false } },
      ];
    }),
    valid: false,
  },
  {
    label: 'invalid: artifacts missing a nullable key',
    doc: variant(baseScanResult, (d) => delete d.artifacts.normalized),
    valid: false,
  },
  { label: 'invalid: negative findings_count', doc: variant(baseScanResult, (d) => (d.findings_count = -1)), valid: false },
];

export const errorEnvelopeCorpus: CorpusEntry[] = [
  { label: 'valid: usage_error', doc: { schema_version: '1', status: 'error', error: { code: 'usage_error', message: 'bad flag' } }, valid: true },
  { label: 'valid: invalid_configuration', doc: { schema_version: '1', status: 'error', error: { code: 'invalid_configuration', message: 'bad config' } }, valid: true },
  { label: 'valid: partial_input_refused', doc: { schema_version: '1', status: 'error', error: { code: 'partial_input_refused', message: 'refused' } }, valid: true },
  { label: 'valid: invalid_report', doc: { schema_version: '1', status: 'error', error: { code: 'invalid_report', message: 'head report failed schema validation' } }, valid: true },
  { label: 'valid: incompatible_reports', doc: { schema_version: '1', status: 'error', error: { code: 'incompatible_reports', message: 'producers differ' } }, valid: true },
  { label: 'invalid: unknown error code', doc: { schema_version: '1', status: 'error', error: { code: 'boom', message: 'x' } }, valid: false },
  { label: 'invalid: status not error', doc: { schema_version: '1', status: 'ok', error: { code: 'usage_error', message: 'x' } }, valid: false },
  { label: 'invalid: unknown key in envelope', doc: { schema_version: '1', status: 'error', error: { code: 'usage_error', message: 'x' }, details: {} }, valid: false },
  { label: 'invalid: unknown key in error body', doc: { schema_version: '1', status: 'error', error: { code: 'usage_error', message: 'x', stack: 'y' } }, valid: false },
  { label: 'invalid: missing message', doc: { schema_version: '1', status: 'error', error: { code: 'usage_error' } }, valid: false },
  { label: 'invalid: wrong schema_version literal', doc: { schema_version: '2', status: 'error', error: { code: 'usage_error', message: 'x' } }, valid: false },
  { label: 'invalid: missing error body', doc: { schema_version: '1', status: 'error' }, valid: false },
  { label: 'invalid: error code is not a string', doc: { schema_version: '1', status: 'error', error: { code: 1, message: 'x' } }, valid: false },
];

const baseDoctor = {
  schema_version: '1',
  command: 'doctor',
  ok: true,
  tools: [
    { name: 'semgrep', status: 'ready', version: '1.x.y', problems: [] },
    { name: 'zap', status: 'ready', version: '2.x.y', api_key: 'present', api_key_verified: false, problems: [] },
  ],
};

export const doctorCorpus: CorpusEntry[] = [
  { label: 'valid: both tools ready', doc: baseDoctor, valid: true },
  {
    label: 'valid: skipped tool with null version',
    doc: variant(baseDoctor, (d) => {
      d.tools[1] = { name: 'zap', status: 'skipped', version: null, problems: [] };
    }),
    valid: true,
  },
  {
    label: 'valid: unavailable semgrep with a problem',
    doc: variant(baseDoctor, (d) => {
      d.ok = false;
      d.tools[0] = { name: 'semgrep', status: 'unavailable', version: null, problems: [{ code: 'tool_unavailable', message: 'not found' }] };
    }),
    valid: true,
  },
  {
    label: 'valid: zap with missing key',
    doc: variant(baseDoctor, (d) => {
      d.ok = false;
      d.tools[1] = { name: 'zap', status: 'unavailable', version: null, api_key: 'absent', problems: [{ code: 'bad_api_key', message: 'key not set' }] };
    }),
    valid: true,
  },
  { label: 'valid: no tools', doc: variant(baseDoctor, (d) => (d.tools = [])), valid: true },
  { label: 'invalid: unknown tool name', doc: variant(baseDoctor, (d) => (d.tools[0].name = 'bandit')), valid: false },
  { label: 'invalid: unknown tool status', doc: variant(baseDoctor, (d) => (d.tools[0].status = 'up')), valid: false },
  { label: 'invalid: problem code not in the diagnostic list', doc: variant(baseDoctor, (d) => (d.tools[0].problems = [{ code: 'boom', message: 'x' }])), valid: false },
  { label: 'invalid: api_key not present or absent', doc: variant(baseDoctor, (d) => (d.tools[1].api_key = 'maybe')), valid: false },
  { label: 'invalid: api_key_verified not boolean', doc: variant(baseDoctor, (d) => (d.tools[1].api_key_verified = 'no')), valid: false },
  { label: 'invalid: tool missing version', doc: variant(baseDoctor, (d) => delete d.tools[0].version), valid: false },
  { label: 'invalid: unknown key on a tool', doc: variant(baseDoctor, (d) => (d.tools[0].path = '/bin/semgrep')), valid: false },
  { label: 'invalid: wrong command literal', doc: variant(baseDoctor, (d) => (d.command = 'scan')), valid: false },
  { label: 'invalid: missing ok', doc: variant(baseDoctor, (d) => delete d.ok), valid: false },
];

const baseFindingReference = {
  rule_id: 'rules.sql-injection',
  producer_reference: null,
  title: text('rules.sql-injection'),
  fingerprint_quality: 'exact',
  severity: 'high',
  severity_original: 'ERROR',
  severity_complete: true,
  confidence: null,
  occurrence_count: 1,
  occurrence_severities: ['ERROR'],
};

const baseCompareInput = {
  producer_version: '1.100.0',
  completeness: 'complete',
  authoritative: true,
  non_authoritative_reasons: [],
  asserted_revision: null,
};

const baseCompare = {
  command: 'compare',
  authoritative: true,
  non_authoritative_reasons: [],
  base: baseCompareInput,
  head: baseCompareInput,
  summary: {
    new: 0,
    resolved: 0,
    unchanged: 0,
    changed: 0,
    severity_increased: 0,
    severity_decreased: 0,
    incomparable: 0,
    severity_comparison_incomparable: 0,
  },
  findings: [] as unknown[],
  metadata: { configuration_digest_equal: true },
};

export const compareCorpus: CorpusEntry[] = [
  { label: 'valid: identical empty comparison', doc: baseCompare, valid: true },
  {
    label: 'valid: head-only finding is new',
    doc: variant(baseCompare, (d) => {
      d.summary.new = 1;
      d.findings = [
        {
          fingerprint: `v1:${digest('f-new')}`,
          state: 'new',
          severity_comparison: 'incomparable',
          changed_fields: [],
          base: null,
          head: baseFindingReference,
        },
      ];
    }),
    valid: true,
  },
  {
    label: 'valid: changed finding with comparable severity and asserted revisions',
    doc: variant(baseCompare, (d) => {
      d.base = { ...baseCompareInput, asserted_revision: { value: 'v2.0', asserted: true } };
      d.head = { ...baseCompareInput, asserted_revision: { value: 'v2.1', asserted: true } };
      d.summary.changed = 1;
      d.findings = [
        {
          fingerprint: `v1:${digest('f-changed')}`,
          state: 'changed',
          severity_comparison: 'comparable',
          changed_fields: ['confidence'],
          base: baseFindingReference,
          head: { ...baseFindingReference, confidence: text('Low') },
        },
      ];
    }),
    valid: true,
  },
  {
    label: 'valid: non-authoritative partial input with reasons',
    doc: variant(baseCompare, (d) => {
      d.authoritative = false;
      d.non_authoritative_reasons = ['partial_input_allowed', 'base_input_non_authoritative'];
      d.base = { ...baseCompareInput, completeness: 'partial', authoritative: false, non_authoritative_reasons: ['partial_scan'] };
      d.metadata = { configuration_digest_equal: false };
    }),
    valid: true,
  },
  {
    label: 'valid: fingerprint-version incomparable entry',
    doc: variant(baseCompare, (d) => {
      d.summary.incomparable = 1;
      d.summary.severity_comparison_incomparable = 1;
      d.findings = [
        {
          fingerprint: `v1:${digest('f-inc')}`,
          state: 'incomparable',
          severity_comparison: 'incomparable',
          changed_fields: [],
          base: baseFindingReference,
          head: null,
        },
      ];
    }),
    valid: true,
  },
  { label: 'invalid: unknown top-level key', doc: variant(baseCompare, (d) => (d.extra = 1)), valid: false },
  { label: 'invalid: unknown state', doc: variant(baseCompare, (d) => (d.summary.added = 0)), valid: false },
  { label: 'invalid: float summary count', doc: variant(baseCompare, (d) => (d.summary.new = 1.5)), valid: false },
  { label: 'invalid: asserted revision not marked asserted', doc: variant(baseCompare, (d) => (d.base.asserted_revision = { value: 'v1', asserted: false })), valid: false },
  { label: 'invalid: changed field not in the closed list', doc: variant(baseCompare, (d) => (d.findings = [{ fingerprint: `v1:${digest('x')}`, state: 'changed', severity_comparison: 'comparable', changed_fields: ['description'], base: baseFindingReference, head: baseFindingReference }])), valid: false },
  { label: 'invalid: base section with an extra key', doc: variant(baseCompare, (d) => (d.base.target = { kind: 'git' })), valid: false },
  { label: 'invalid: missing configuration_digest_equal', doc: variant(baseCompare, (d) => (d.metadata = {})), valid: false },
  { label: 'invalid: severity_comparison not in the closed list', doc: variant(baseCompare, (d) => (d.findings = [{ fingerprint: `v1:${digest('x')}`, state: 'new', severity_comparison: 'maybe', changed_fields: [], base: null, head: baseFindingReference }])), valid: false },
  { label: 'invalid: wrong completeness on base', doc: variant(baseCompare, (d) => (d.base.completeness = 'done')), valid: false },
  { label: 'invalid: wrong command literal', doc: variant(baseCompare, (d) => (d.command = 'scan')), valid: false },
];
