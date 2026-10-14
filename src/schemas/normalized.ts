import { z } from 'zod';
import { FINGERPRINT_QUALITIES } from '../contracts/enums.js';
import {
  completeness,
  contentTrust,
  count,
  fingerprint,
  producer,
  scanReason,
  schemaVersion,
  severity,
  sha256Hex,
  TextFieldSchema,
} from './common.js';

export const GitTargetSchema = z.strictObject({
  kind: z.literal('git'),
  relative_path: z.string(),
  revision: z.string().nullable(),
  dirty: z.boolean().nullable(),
  content_digest: sha256Hex.nullable(),
});

export const DirectoryTargetSchema = z.strictObject({
  kind: z.literal('directory'),
  relative_path: z.string(),
  content_digest: sha256Hex.nullable(),
});

export const HttpOriginTargetSchema = z.strictObject({
  kind: z.literal('http_origin'),
  origin: z.string(),
  asserted_revision: z.string().optional(),
});

export const TargetSchema = z.discriminatedUnion('kind', [
  GitTargetSchema,
  DirectoryTargetSchema,
  HttpOriginTargetSchema,
]);

export const SourceLocationSchema = z.strictObject({
  path: z.string(),
  start_line: count,
  start_col: count,
  end_line: count,
  end_col: count,
});

export const RuntimeLocationSchema = z.strictObject({
  url: z.string(),
  method: z.string(),
  param: z.string(),
});

/** Evidence keys depend on the producer: Semgrep sends `snippet`, ZAP sends the others. */
export const EvidenceSchema = z.strictObject({
  snippet: TextFieldSchema.nullable().optional(),
  attack: TextFieldSchema.nullable().optional(),
  evidence: TextFieldSchema.nullable().optional(),
  message_id: z.string().optional(),
});

export const OccurrenceSchema = z.strictObject({
  severity,
  severity_original: z.string(),
  source_location: SourceLocationSchema.optional(),
  runtime_location: RuntimeLocationSchema.optional(),
  evidence: EvidenceSchema,
});

export const FindingSchema = z.strictObject({
  fingerprint,
  fingerprint_quality: z.enum(FINGERPRINT_QUALITIES),
  producer_fingerprint: z.string().optional(),
  rule_id: z.string(),
  producer_reference: z.string().nullable(),
  title: TextFieldSchema,
  description: TextFieldSchema.optional(),
  severity,
  severity_original: z.string(),
  severity_complete: z.boolean(),
  confidence: TextFieldSchema.nullable(),
  category: z.string().nullable().optional(),
  references: z.array(z.string()).optional(),
  status: z.literal('open'),
  redactions_applied: z.boolean().optional(),
  occurrence_count: count,
  occurrences: z.array(OccurrenceSchema),
});

/** Counts of redactions keyed by rule id; never values. */
export const RedactionSummarySchema = z.record(z.string(), count);

export const NormalizedDocumentSchema = z.strictObject({
  schema_version: schemaVersion,
  content_trust: contentTrust,
  producer,
  producer_version: z.string().nullable(),
  target: TargetSchema,
  completeness,
  authoritative: z.boolean(),
  non_authoritative_reasons: z.array(scanReason),
  // Versions are strings, not literals: compare must accept mismatched versions.
  fingerprint_version: z.string(),
  severity_mapping_version: z.string(),
  redaction_policy_version: z.string(),
  rules_digest: sha256Hex.nullable(),
  configuration_digest: sha256Hex,
  raw_sha256_before_redaction: sha256Hex,
  raw_sha256_after_redaction: sha256Hex,
  redaction_summary: RedactionSummarySchema,
  findings: z.array(FindingSchema),
});
