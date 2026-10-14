import type { z } from 'zod';
import { DiagnosticDetailSchema, DiagnosticSchema, TextFieldSchema } from './common.js';
import {
  AssertedRevisionSchema,
  CompareFindingSchema,
  CompareInputSchema,
  CompareMetadataSchema,
  CompareResultSchema,
  CompareSummarySchema,
  FindingReferenceSchema,
} from './compare.js';
import {
  DoctorResultSchema,
  DoctorToolSchema,
  ErrorBodySchema,
  ErrorEnvelopeSchema,
  ProblemSchema,
} from './envelopes.js';
import {
  DirectoryTargetSchema,
  EvidenceSchema,
  FindingSchema,
  GitTargetSchema,
  HttpOriginTargetSchema,
  NormalizedDocumentSchema,
  OccurrenceSchema,
  RuntimeLocationSchema,
  SourceLocationSchema,
  TargetSchema,
} from './normalized.js';
import { ArtifactsSchema, ExclusionSchema, ScanResultSchema } from './scan-result.js';

export * from './common.js';
export * from './compare.js';
export * from './envelopes.js';
export * from './normalized.js';
export * from './scan-result.js';
export { emitJsonSchema, renderSchemaFile } from './json-schema.js';

/** Every object type by name; T05 uses this to prove the field-order lists cover each Zod key. */
export const OBJECT_TYPES: Record<string, z.ZodObject> = {
  TextField: TextFieldSchema,
  DiagnosticDetail: DiagnosticDetailSchema,
  Diagnostic: DiagnosticSchema,
  GitTarget: GitTargetSchema,
  DirectoryTarget: DirectoryTargetSchema,
  HttpOriginTarget: HttpOriginTargetSchema,
  SourceLocation: SourceLocationSchema,
  RuntimeLocation: RuntimeLocationSchema,
  Evidence: EvidenceSchema,
  Occurrence: OccurrenceSchema,
  Finding: FindingSchema,
  NormalizedDocument: NormalizedDocumentSchema,
  Exclusion: ExclusionSchema,
  Artifacts: ArtifactsSchema,
  ScanResult: ScanResultSchema,
  ErrorBody: ErrorBodySchema,
  ErrorEnvelope: ErrorEnvelopeSchema,
  Problem: ProblemSchema,
  DoctorTool: DoctorToolSchema,
  DoctorResult: DoctorResultSchema,
  FindingReference: FindingReferenceSchema,
  CompareFinding: CompareFindingSchema,
  AssertedRevision: AssertedRevisionSchema,
  CompareInput: CompareInputSchema,
  CompareSummary: CompareSummarySchema,
  CompareMetadata: CompareMetadataSchema,
  CompareResult: CompareResultSchema,
};

export type TextField = z.infer<typeof TextFieldSchema>;
export type Diagnostic = z.infer<typeof DiagnosticSchema>;
export type Target = z.infer<typeof TargetSchema>;
export type Occurrence = z.infer<typeof OccurrenceSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type NormalizedDocument = z.infer<typeof NormalizedDocumentSchema>;
export type ScanResult = z.infer<typeof ScanResultSchema>;
export type ErrorEnvelope = z.infer<typeof ErrorEnvelopeSchema>;
export type DoctorResult = z.infer<typeof DoctorResultSchema>;
export type CompareResult = z.infer<typeof CompareResultSchema>;
export type FindingReference = z.infer<typeof FindingReferenceSchema>;
export type CompareFinding = z.infer<typeof CompareFindingSchema>;

/** Documents that get a committed `schemas/<name>.schema.json`. */
export const SCHEMA_DOCUMENTS = [
  { name: 'normalized', schema: NormalizedDocumentSchema },
  { name: 'scan-result', schema: ScanResultSchema },
  { name: 'error-envelope', schema: ErrorEnvelopeSchema },
  { name: 'doctor-result', schema: DoctorResultSchema },
  { name: 'compare-result', schema: CompareResultSchema },
] as const;
