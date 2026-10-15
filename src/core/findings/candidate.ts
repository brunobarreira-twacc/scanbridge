import type { Candidate } from '../../contracts/adapter.js';
import { SNIPPET_FIELD_MAX, TEXT_FIELD_MAX } from '../../contracts/limits.js';
import type { Occurrence, TextField } from '../../schemas/index.js';
import {
  canonicalizeSnippet,
  fingerprintFromMaterial,
  guardIdentity,
  normalizeUrl,
  semgrepDegraded,
  semgrepExact,
  sha256Hex,
  zap,
  type FingerprintMaterial,
  type GuardedIdentity,
  type IdentityKind,
} from '../fingerprints/index.js';
import { plainText, textField } from './text.js';

/** Identity placeholders and unreadable sources seen while resolving one candidate. */
export interface CandidateIssues {
  oversized: number;
  invalid: number;
  unreadableSource: boolean;
}

/** A candidate with its fingerprint, its stored identity values and its occurrence, ready to group. */
export interface ResolvedCandidate {
  fingerprint: string;
  degraded: boolean;
  ruleId: string;
  producerReference: string | null;
  producerFingerprint: string | null;
  occurrence: Occurrence;
  title: TextField;
  description: TextField | null;
  confidence: TextField | null;
  category: string | null;
  /** Raw, unsanitized: the finding-level pass sanitizes, bounds and deduplicates them. */
  references: string[];
  redactionsApplied: boolean;
  issues: CandidateIssues;
}

interface ResolvedFingerprint {
  fingerprint: string;
  degraded: boolean;
  ruleId: string;
  producerReference: string | null;
  occurrence: Occurrence;
}

export function resolveCandidate(candidate: Candidate): ResolvedCandidate {
  const issues: CandidateIssues = { oversized: 0, invalid: 0, unreadableSource: false };
  const resolved = candidate.producer === 'semgrep' ? resolveSemgrep(candidate, issues) : resolveZap(candidate, issues);
  return {
    ...resolved,
    producerFingerprint: candidate.producerFingerprint === null ? null : plainText(candidate.producerFingerprint),
    title: textField(candidate.title, TEXT_FIELD_MAX),
    description: candidate.description === null ? null : textField(candidate.description, TEXT_FIELD_MAX),
    confidence: candidate.confidence === null ? null : textField(candidate.confidence, TEXT_FIELD_MAX),
    category: candidate.category === null ? null : plainText(candidate.category),
    references: candidate.references,
    redactionsApplied: candidate.redactionsApplied,
    issues,
  };
}

function resolveSemgrep(candidate: Candidate, issues: CandidateIssues): ResolvedFingerprint {
  const source = candidate.location.source;
  if (!source) throw new TypeError('semgrep candidate has no source location');

  const rule = guard(candidate.ruleId, 'rule_id', issues);
  const path = guard(source.path, 'path', issues);
  const { startLine, startCol, endLine, endCol } = source;
  const degradedMaterial = (): FingerprintMaterial =>
    semgrepDegraded(rule.value, path.value, startLine, startCol, endLine, endCol);

  // An over-limit or invalid path skips the source read, so the location-based material is used.
  let material: FingerprintMaterial;
  let degraded: boolean;
  const snippet = candidate.snippet;
  if (rule.degraded || path.degraded) {
    material = degradedMaterial();
    degraded = true;
  } else if (snippet?.ok) {
    material = semgrepExact(rule.value, path.value, canonicalizeSnippet(snippet.text));
    degraded = false;
  } else {
    material = degradedMaterial();
    degraded = true;
    issues.unreadableSource = true;
  }

  return {
    fingerprint: fingerprintFromMaterial(material),
    degraded,
    ruleId: rule.value,
    producerReference: null,
    occurrence: {
      severity: candidate.severity,
      severity_original: plainText(candidate.severityOriginal),
      source_location: {
        path: path.value,
        start_line: startLine,
        start_col: startCol,
        end_line: endLine,
        end_col: endCol,
      },
      evidence: buildEvidence(candidate),
    },
  };
}

function resolveZap(candidate: Candidate, issues: CandidateIssues): ResolvedFingerprint {
  const runtime = candidate.location.runtime;
  if (!runtime) throw new TypeError('zap candidate has no runtime location');

  const rule = guard(candidate.ruleId, 'rule_id', issues);
  const reference = resolveProducerReference(candidate.producerReference, issues);
  const method = guard(runtime.method, 'method', issues);
  const param = guard(runtime.param, 'param', issues);
  const url = resolveUrl(runtime.url, issues);

  const degraded = reference.degraded || rule.degraded || method.degraded || param.degraded || url.degraded;
  const material = zap(rule.value, reference.material, method.value, url.targetPath, param.value);

  return {
    fingerprint: fingerprintFromMaterial(material),
    degraded,
    ruleId: rule.value,
    producerReference: reference.value,
    occurrence: {
      severity: candidate.severity,
      severity_original: plainText(candidate.severityOriginal),
      runtime_location: { url: url.url, method: method.value, param: param.value },
      evidence: buildEvidence(candidate),
    },
  };
}

/** A missing, empty or non-string `alertRef` is degraded with an empty material; it is not a warning. */
function resolveProducerReference(
  value: string | null,
  issues: CandidateIssues,
): { value: string | null; material: string; degraded: boolean } {
  if (typeof value !== 'string' || value === '') return { value: null, material: '', degraded: true };
  const guarded = guard(value, 'producer_reference', issues);
  return { value: guarded.value, material: guarded.value, degraded: guarded.degraded };
}

/**
 * Stored `url` is the normalized URL. An over-limit URL makes both `url` and
 * `targetPath` the same placeholder. A URL that cannot be normalized is invalid.
 */
function resolveUrl(
  raw: string,
  issues: CandidateIssues,
): { url: string; targetPath: string; degraded: boolean } {
  let normalized;
  try {
    normalized = normalizeUrl(raw);
  } catch {
    issues.invalid++;
    const placeholder = `[invalid:${sha256Hex(raw)}]`;
    return { url: placeholder, targetPath: placeholder, degraded: true };
  }

  const url = guard(normalized.url, 'url', issues);
  if (url.degraded) return { url: url.value, targetPath: url.value, degraded: true };

  const targetPath = guard(normalized.targetPath, 'url', issues);
  return { url: url.value, targetPath: targetPath.value, degraded: targetPath.degraded };
}

function guard(value: string, kind: IdentityKind, issues: CandidateIssues): GuardedIdentity {
  const guarded = guardIdentity(value, kind);
  if (guarded.degraded) {
    if (guarded.reason === 'oversized') issues.oversized++;
    else issues.invalid++;
  }
  return guarded;
}

/**
 * Evidence keys are restricted to the schema's: `snippet` comes from the source
 * read, `attack` and `evidence` are structured, `message_id` is plain. Other
 * producer keys (for example Semgrep's `producer_lines`) are not part of the schema.
 */
function buildEvidence(candidate: Candidate): Occurrence['evidence'] {
  const evidence: Occurrence['evidence'] = {};
  const snippet = candidate.snippet;
  if (snippet?.ok) evidence.snippet = textField(snippet.text, SNIPPET_FIELD_MAX);

  for (const [key, value] of Object.entries(candidate.evidence)) {
    if (key === 'message_id') {
      if (value !== null) evidence.message_id = plainText(value);
    } else if (key === 'attack' || key === 'evidence') {
      evidence[key] = value === null ? null : textField(value, SNIPPET_FIELD_MAX);
    }
  }
  return evidence;
}
