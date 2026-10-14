import { z } from 'zod';
import { COMPARE_REASONS, FINGERPRINT_QUALITIES } from '../contracts/enums.js';
import {
  completeness,
  count,
  fingerprint,
  scanReason,
  severity,
  TextFieldSchema,
} from './common.js';

/** Finding fields that `changed_fields` may name (spec 07). */
export const CHANGED_FIELDS = [
  'confidence',
  'evidence',
  'occurrence_count',
  'occurrence_severities',
  'severity_original',
  'title',
] as const;

export const FindingReferenceSchema = z.strictObject({
  rule_id: z.string(),
  producer_reference: z.string().nullable(),
  title: TextFieldSchema,
  fingerprint_quality: z.enum(FINGERPRINT_QUALITIES),
  severity,
  severity_original: z.string(),
  severity_complete: z.boolean(),
  confidence: TextFieldSchema.nullable(),
  occurrence_count: count,
  occurrence_severities: z.array(z.string()),
});

export const CompareFindingSchema = z.strictObject({
  fingerprint,
  state: z.enum([
    'new',
    'resolved',
    'unchanged',
    'changed',
    'severity_increased',
    'severity_decreased',
    'incomparable',
  ]),
  severity_comparison: z.enum(['comparable', 'incomparable']),
  changed_fields: z.array(z.enum(CHANGED_FIELDS)),
  base: FindingReferenceSchema.nullable(),
  head: FindingReferenceSchema.nullable(),
});

/** Caller-asserted revision; never identity evidence (spec 07). */
export const AssertedRevisionSchema = z.strictObject({
  value: z.string(),
  asserted: z.literal(true),
});

export const CompareInputSchema = z.strictObject({
  producer_version: z.string().nullable(),
  completeness,
  authoritative: z.boolean(),
  non_authoritative_reasons: z.array(scanReason),
  asserted_revision: AssertedRevisionSchema.nullable(),
});

export const CompareSummarySchema = z.strictObject({
  new: count,
  resolved: count,
  unchanged: count,
  changed: count,
  severity_increased: count,
  severity_decreased: count,
  incomparable: count,
  severity_comparison_incomparable: count,
});

export const CompareMetadataSchema = z.strictObject({
  configuration_digest_equal: z.boolean(),
});

export const CompareResultSchema = z.strictObject({
  command: z.literal('compare'),
  authoritative: z.boolean(),
  non_authoritative_reasons: z.array(z.enum(COMPARE_REASONS)),
  base: CompareInputSchema,
  head: CompareInputSchema,
  summary: CompareSummarySchema,
  findings: z.array(CompareFindingSchema),
  metadata: CompareMetadataSchema,
});
