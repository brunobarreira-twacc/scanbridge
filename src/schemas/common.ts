import { z } from 'zod';
import {
  COMPLETENESS,
  DIAGNOSTIC_CODES,
  SCAN_REASONS,
  SEVERITIES,
  SCHEMA_VERSION,
} from '../contracts/enums.js';

export const schemaVersion = z.literal(SCHEMA_VERSION);

export const completeness = z.enum(COMPLETENESS);
export const severity = z.enum(SEVERITIES);
export const scanReason = z.enum(SCAN_REASONS);
export const diagnosticCode = z.enum(DIAGNOSTIC_CODES);

export const producer = z.enum(['semgrep', 'zap', 'sonarqube']);
export const contentTrust = z.literal('untrusted_producer_content');

/** Lowercase SHA-256 hex digest. */
export const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/);

/** `v<n>:` plus lowercase SHA-256 hex; the prefix is the fingerprint version. */
export const fingerprint = z.string().regex(/^v[0-9]+:[0-9a-f]{64}$/);

/** Non-negative integer; floats are rejected. */
export const count = z.int().nonnegative();

export const textFieldShape = {
  text: z.string(),
  truncated: z.boolean(),
  original_length: count,
};

export const TextFieldSchema = z.strictObject(textFieldShape);

export const DiagnosticDetailSchema = z.strictObject({
  ...textFieldShape,
  untrusted: z.literal(true),
});

export const DiagnosticSchema = z.strictObject({
  code: diagnosticCode,
  level: z.enum(['info', 'warn', 'error']),
  tool: producer.optional(),
  message: z.string(),
  detail: DiagnosticDetailSchema.optional(),
});
