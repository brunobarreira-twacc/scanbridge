import type { DiagnosticCode, ErrorCode } from '../contracts/enums.js';
import { SCHEMA_VERSION } from '../contracts/enums.js';
import { serializeCanonical } from '../core/serialization/index.js';
import { CompareResultSchema, type CompareResult, ErrorEnvelopeSchema } from '../schemas/index.js';

/** Each helper returns the complete stdout text: one JSON document and a trailing newline. */

export function errorEnvelope(code: ErrorCode, message: string): string {
  const envelope = ErrorEnvelopeSchema.parse({
    schema_version: SCHEMA_VERSION,
    status: 'error',
    error: { code, message },
  });
  return serializeCanonical('ErrorEnvelope', envelope);
}

/** Spec 03 `api_key` values are `present` | `missing`; `DoctorToolSchema` still says `absent` (handoff blocker). */
export type DoctorReport = {
  schema_version: typeof SCHEMA_VERSION;
  command: 'doctor';
  ok: boolean;
  tools: DoctorToolReport[];
};

export type DoctorToolReport = {
  name: 'semgrep' | 'zap';
  status: 'ready' | 'unavailable' | 'skipped';
  version: string | null;
  api_key?: 'present' | 'missing';
  api_key_verified?: boolean;
  problems: { code: DiagnosticCode; message: string }[];
};

/** Not validated against `DoctorResultSchema` until the `api_key` contract is fixed. */
export function doctorEnvelope(report: DoctorReport): string {
  return serializeCanonical('DoctorResult', report);
}

export function compareEnvelope(result: CompareResult): string {
  return serializeCanonical('CompareResult', CompareResultSchema.parse(result));
}
