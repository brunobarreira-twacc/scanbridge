import { z } from 'zod';
import { EXIT_CODES } from '../contracts/enums.js';
import {
  completeness,
  count,
  DiagnosticSchema,
  producer,
  scanReason,
  schemaVersion,
} from './common.js';

/** Shape of one `exclusions[]` entry is not specified in spec 03; this is a provisional minimum. */
export const ExclusionSchema = z.strictObject({
  path: z.string(),
  reason: z.string(),
});

export const ArtifactsSchema = z.strictObject({
  directory: z.string().nullable(),
  raw: z.array(z.string()).nullable(),
  normalized: z.string().nullable(),
});

/** Exit codes a `scan` envelope can carry (spec 03: exit 1 and 5 print the error envelope instead). */
export const ScanExitCodeSchema = z.union([
  z.literal(EXIT_CODES.OK),
  z.literal(EXIT_CODES.TOOL_UNAVAILABLE),
  z.literal(EXIT_CODES.SCAN_FAILED),
  z.literal(EXIT_CODES.PARTIAL),
]);

export const ScanResultSchema = z.strictObject({
  schema_version: schemaVersion,
  command: z.literal('scan'),
  status: completeness,
  exit_code: ScanExitCodeSchema,
  scan_id: z.string(),
  adapter: producer,
  started_at: z.string(),
  finished_at: z.string(),
  duration_ms: count,
  authoritative: z.boolean(),
  non_authoritative_reasons: z.array(scanReason),
  findings_count: count,
  exclusions: z.array(ExclusionSchema),
  diagnostics: z.array(DiagnosticSchema),
  artifacts: ArtifactsSchema,
});
