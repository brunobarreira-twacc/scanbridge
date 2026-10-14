import { z } from 'zod';
import { ERROR_CODES } from '../contracts/enums.js';
import { diagnosticCode, producer, schemaVersion } from './common.js';

export const ErrorBodySchema = z.strictObject({
  code: z.enum(ERROR_CODES),
  message: z.string(),
});

export const ErrorEnvelopeSchema = z.strictObject({
  schema_version: schemaVersion,
  status: z.literal('error'),
  error: ErrorBodySchema,
});

export const ProblemSchema = z.strictObject({
  code: diagnosticCode,
  message: z.string(),
});

/** Tool-level readiness; `unavailable` covers a failed probe, `skipped` a disabled tool (spec 03). */
export const DoctorToolSchema = z.strictObject({
  name: producer,
  status: z.enum(['ready', 'unavailable', 'skipped']),
  version: z.string().nullable(),
  api_key: z.enum(['present', 'absent']).optional(),
  api_key_verified: z.boolean().optional(),
  problems: z.array(ProblemSchema),
});

export const DoctorResultSchema = z.strictObject({
  schema_version: schemaVersion,
  command: z.literal('doctor'),
  ok: z.boolean(),
  tools: z.array(DoctorToolSchema),
});
