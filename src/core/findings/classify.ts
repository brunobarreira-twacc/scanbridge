import type { NormalizeOutput, RawDiagnostic, ScanOutput } from '../../contracts/adapter.js';
import type { Completeness, ScanReason } from '../../contracts/enums.js';
import { compareCodePoints } from '../fingerprints/occurrences.js';
import type { BuildFindingsResult } from './build.js';

export interface ClassifyInput {
  normalize: Pick<NormalizeOutput, 'completeness' | 'unusableCount' | 'coverageLoss' | 'reasons'>;
  scan: Pick<ScanOutput, 'coverageLoss' | 'reasons'>;
  findings: Pick<BuildFindingsResult, 'coverageLoss' | 'reasons'>;
  /** Findings that remain after building, so 0 means none remain. */
  findingCount: number;
}

export interface Classification {
  completeness: Completeness;
  authoritative: boolean;
  non_authoritative_reasons: ScanReason[];
  /** Operational diagnostics this step adds (unusable entries). Finalize them before output. */
  diagnostics: RawDiagnostic[];
}

/**
 * Final completeness and authority. `failed` when the normalizer failed, or when
 * unusable entries remain and no findings do. `partial` on coverage loss or unusable
 * entries with findings left. Otherwise the normalizer's value stands (`unverified`
 * stays `unverified`). Authoritative only when complete with no reasons.
 */
export function classify(input: ClassifyInput): Classification {
  const { normalize, scan, findings, findingCount } = input;
  const unusable = normalize.unusableCount;
  const hasCoverageLoss =
    normalize.coverageLoss.length + scan.coverageLoss.length + findings.coverageLoss.length > 0;

  let completeness: Completeness;
  if (normalize.completeness === 'failed' || (unusable > 0 && findingCount === 0)) {
    completeness = 'failed';
  } else if (normalize.completeness === 'partial' || hasCoverageLoss || unusable > 0) {
    completeness = 'partial';
  } else {
    completeness = normalize.completeness;
  }

  const reasons = new Set<ScanReason>([...normalize.reasons, ...scan.reasons, ...findings.reasons]);
  if (completeness === 'partial') reasons.add('partial_scan');
  const sortedReasons = [...reasons].sort(compareCodePoints);

  const diagnostics: RawDiagnostic[] = [];
  if (unusable > 0) {
    diagnostics.push({
      code: 'malformed_report',
      level: 'warn',
      message: `${unusable} entries lack required identity values and were excluded`,
    });
  }

  return {
    completeness,
    authoritative: completeness === 'complete' && sortedReasons.length === 0,
    non_authoritative_reasons: sortedReasons,
    diagnostics,
  };
}
