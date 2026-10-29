import type { Adapter, Deps, NormalizeContext, RawDiagnostic, ScanOutput } from '../../contracts/adapter.js';
import { EXIT_CODES, FINGERPRINT_VERSION, type Completeness, type JsonValue, type ScanReason } from '../../contracts/enums.js';
import type { Runner, SourceText } from '../../contracts/ports.js';
import { sha256Hex } from '../../core/fingerprints/index.js';
import { buildFindings, classify } from '../../core/findings/index.js';
import { redactText, redactTree, type Summary } from '../../core/redaction/index.js';
import { serializeCanonical, serializeRaw, sha256Utf8 } from '../../core/serialization/index.js';
import { NormalizedDocumentSchema, type NormalizedDocument } from '../../schemas/index.js';
import type { CliDeps, CliPorts } from '../main.js';
import { FsSourceReader } from '../ports/source-reader.js';
import { FsTargetIdentityReader } from '../ports/target-identity.js';
import type { ReportStore, StoredArtifact } from '../store/report-store.js';
import type { Plan } from './inputs.js';
import { normalizedTooLarge, rawTooLarge } from './limits.js';
import { readOfflineReport } from './offline.js';
import type { ScanExit } from './result.js';

/** [verify] V9: no limit for `git` calls exists in `limits.ts`; revisited with real fixtures. */
const GIT_TIMEOUT_MS = 30_000;

export type PipelineResult = {
  status: Completeness;
  exitCode: ScanExit;
  authoritative: boolean;
  reasons: ScanReason[];
  findingsCount: number;
  diagnostics: RawDiagnostic[];
  raw: string[];
  normalized: string | null;
};

type Identity = Awaited<ReturnType<FsTargetIdentityReader['read']>>;

class Stop extends Error {
  constructor(
    readonly exitCode: ScanExit,
    readonly diagnostics: RawDiagnostic[],
    readonly reasons: ScanReason[] = [],
  ) {
    super('scan stopped');
  }
}

const diagnostic = (code: RawDiagnostic['code'], level: RawDiagnostic['level'], message: string, tool?: 'semgrep' | 'zap' | 'sonarqube'): RawDiagnostic =>
  tool === undefined ? { code, level, message } : { code, level, tool, message };

/**
 * Steps 2 to 11 of the scan pipeline (spec 02) after the scan directory exists. Never throws:
 * every failure becomes a result, so `scan-result.json` can still be written.
 */
export async function runPipeline(plan: Plan, store: ReportStore, deps: CliDeps, ports: CliPorts): Promise<PipelineResult> {
  const raw: string[] = [];
  const diagnostics: RawDiagnostic[] = [...plan.preDiagnostics];
  const tool = plan.adapter;
  try {
    return await execute(plan, store, deps, ports, raw, diagnostics);
  } catch (error) {
    if (error instanceof Stop) {
      return {
        status: 'failed',
        exitCode: error.exitCode,
        authoritative: false,
        reasons: error.reasons,
        findingsCount: 0,
        diagnostics: [...diagnostics, ...error.diagnostics],
        raw,
        normalized: null,
      };
    }
    // Nothing from the thrown value is copied: it may carry producer or source text.
    return {
      status: 'failed',
      exitCode: EXIT_CODES.SCAN_FAILED,
      authoritative: false,
      reasons: [],
      findingsCount: 0,
      diagnostics: [...diagnostics, diagnostic('tool_execution_failed', 'error', 'The scan could not be completed because of an internal error', tool)],
      raw,
      normalized: null,
    };
  }
}

async function execute(
  plan: Plan,
  store: ReportStore,
  deps: CliDeps,
  ports: CliPorts,
  rawFiles: string[],
  diagnostics: RawDiagnostic[],
): Promise<PipelineResult> {
  const tool = plan.adapter;
  const adapter: Adapter<never, never> = (tool === 'semgrep' ? ports.catalog.semgrep : tool === 'zap' ? ports.catalog.zap : ports.catalog.sonarqube) as unknown as Adapter<never, never>;
  const adapterDeps: Deps = { runner: ports.runner, http: ports.http, clock: deps.clock };
  const semgrep = plan.semgrep;

  // 2. Probe (never for offline ZAP).
  let probeVersion: string | null = null;
  if (plan.mode !== 'offline') {
    const probed = await probe(plan, ports, adapterDeps);
    diagnostics.push(...probed.diagnostics);
    if (probed.status !== 'ready') throw new Stop(EXIT_CODES.TOOL_UNAVAILABLE, []);
    probeVersion = probed.version;
  }

  // 3. Target identity, first reading (Semgrep).
  const identity = semgrep ? targetIdentity(plan, ports.runner) : null;
  const readTarget = async (): Promise<Identity | null> =>
    identity && semgrep ? identity.read({ targetRel: semgrep.scan.targetRel, excludeRel: semgrep.excludeRel }) : null;
  const first = await readTarget();
  if (first) diagnostics.push(...first.diagnostics);

  // 4. Execute, query or read the offline file.
  const scanOut = await acquire(plan, ports, adapterDeps);
  diagnostics.push(...scanOut.diagnostics);
  if (scanOut.outcome !== 'ok') {
    throw new Stop(scanOut.outcome === 'unavailable' ? EXIT_CODES.TOOL_UNAVAILABLE : EXIT_CODES.SCAN_FAILED, [], scanOut.reasons);
  }
  const bytes = scanOut.raw;
  if (bytes === null) throw new Stop(EXIT_CODES.SCAN_FAILED, [diagnostic('tool_execution_failed', 'error', 'The producer returned no output', tool)], scanOut.reasons);
  if (rawTooLarge(bytes.byteLength)) {
    throw new Stop(EXIT_CODES.SCAN_FAILED, [diagnostic('resource_limit_exceeded', 'error', 'The producer output exceeds the raw size limit', tool)], scanOut.reasons);
  }

  // 5. Hash the original producer output.
  const rawBefore = sha256Hex(bytes);

  // 6. Parse, redact, serialize and persist the redacted raw document. Nothing is persisted before this succeeds.
  const parsed = adapter.parse(bytes);
  if (!parsed.ok) {
    const message = parsed.reason === 'invalid_json' ? 'The producer output is not valid JSON' : 'The producer output has an unsupported shape';
    throw new Stop(EXIT_CODES.SCAN_FAILED, [diagnostic('malformed_report', 'error', message, tool)], scanOut.reasons);
  }
  let redacted;
  let rawText: string;
  try {
    redacted = redactTree(parsed.doc, plan.policy, semgrep ? { removePaths: ['results.*.extra.metavars'] } : {});
    rawText = serializeRaw(redacted.value);
  } catch {
    throw new Stop(EXIT_CODES.SCAN_FAILED, [diagnostic('redaction_failed', 'error', 'The producer output could not be redacted safely', tool)], scanOut.reasons);
  }
  const rawAfter = sha256Utf8(rawText);
  const stored = await store.writeRaw(`${tool}.json`, rawText);
  rawFiles.push(stored.relativePath);
  const doc = redacted.value as JsonValue;

  // 7. Semgrep: read and redact the source ranges.
  const { sources, summary: sourceSummary } = semgrep ? await readSources(adapter.sourceRefs(doc), plan) : { sources: new Map<string, SourceText>(), summary: {} };

  // 8-9. Normalize, group and classify.
  const context: NormalizeContext = {
    mode: plan.mode === 'offline' ? 'offline' : 'live',
    targetRel: semgrep?.scan.targetRel ?? '.',
    targetOrigin: plan.targetOrigin,
    producerVersion: plan.offline ? plan.offline.producerVersion : probeVersion,
    redactionTouched: new Set(redacted.touched),
    coverageLoss: scanOut.coverageLoss,
    scanDiagnostics: scanOut.diagnostics,
    scanReasons: scanOut.reasons,
  };
  const normalized = adapter.normalize(doc, context, sources);
  const built = buildFindings(normalized.candidates, { producer: tool });

  // 10. Target identity, second reading.
  const changedLoss: RawDiagnostic[] = [];
  const second = await readTarget();
  if (first && second && first.content_digest !== second.content_digest) {
    changedLoss.push(diagnostic('target_changed_during_scan', 'warn', 'The target content changed while the scan was running', tool));
  }

  const classification = classify({
    normalize: normalized,
    scan: { coverageLoss: [...scanOut.coverageLoss, ...changedLoss], reasons: scanOut.reasons },
    findings: built,
    findingCount: built.findings.length,
  });
  diagnostics.push(
    ...normalized.diagnostics,
    ...normalized.coverageLoss,
    ...changedLoss,
    ...built.diagnostics,
    ...built.coverageLoss,
    ...classification.diagnostics,
  );

  const result = (status: Completeness, exitCode: ScanExit, extra: Partial<PipelineResult> = {}): PipelineResult => ({
    status,
    exitCode,
    authoritative: false,
    reasons: classification.non_authoritative_reasons,
    findingsCount: 0,
    diagnostics,
    raw: rawFiles,
    normalized: null,
    ...extra,
  });
  if (classification.completeness === 'failed') return result('failed', EXIT_CODES.SCAN_FAILED);

  // 11. Persist `normalized.json`.
  const document: NormalizedDocument = NormalizedDocumentSchema.parse({
    schema_version: '1',
    content_trust: 'untrusted_producer_content',
    producer: tool,
    producer_version: normalized.producerVersion,
    target: normalizedTarget(plan, first),
    completeness: classification.completeness,
    authoritative: classification.authoritative,
    non_authoritative_reasons: classification.non_authoritative_reasons,
    fingerprint_version: FINGERPRINT_VERSION,
    severity_mapping_version: normalized.severityMappingVersion,
    redaction_policy_version: plan.policy.version,
    rules_digest: plan.rulesDigest,
    configuration_digest: plan.configurationDigest,
    raw_sha256_before_redaction: rawBefore,
    raw_sha256_after_redaction: rawAfter,
    redaction_summary: mergeSummaries(redacted.summary, sourceSummary),
    findings: built.findings,
  });
  const text = serializeCanonical('NormalizedDocument', document);
  // [verify] V9: over the limit is failed with the raw artifact kept.
  if (normalizedTooLarge(Buffer.byteLength(text, 'utf8'))) {
    diagnostics.push(diagnostic('resource_limit_exceeded', 'error', 'normalized.json would exceed the size limit', tool));
    return result('failed', EXIT_CODES.SCAN_FAILED);
  }
  const normalizedFile: StoredArtifact = await store.writeNormalized(text);

  const exitCode = classification.completeness === 'partial' ? EXIT_CODES.PARTIAL : EXIT_CODES.OK;
  return result(classification.completeness, exitCode, {
    authoritative: classification.authoritative,
    findingsCount: built.findings.length,
    normalized: normalizedFile.relativePath,
  });
}

async function probe(plan: Plan, ports: CliPorts, deps: Deps) {
  const unavailable = (tool: 'semgrep' | 'zap' | 'sonarqube') => ({
    status: 'unavailable' as const,
    version: null,
    diagnostics: [diagnostic('tool_unavailable', 'error', `${tool} probe did not complete`, tool)],
  });
  try {
    if (plan.semgrep) return await ports.catalog.semgrep.probe({ producer: 'semgrep' }, deps);
    if (plan.live) return await ports.catalog.zap.probe(plan.live.probe, deps);
    if (plan.sonarqube) return await ports.catalog.sonarqube.probe(plan.sonarqube.probe, deps);
  } catch {
    return unavailable(plan.adapter);
  }
  return unavailable(plan.adapter);
}

/** Runs the scan, or reads the offline report. The offline path never touches `probe` or `scan`. */
async function acquire(plan: Plan, ports: CliPorts, deps: Deps): Promise<ScanOutput> {
  const failed = (d: RawDiagnostic): ScanOutput => ({ outcome: 'failed', raw: null, diagnostics: [d], coverageLoss: [], reasons: [] });
  if (plan.semgrep) return ports.catalog.semgrep.scan(plan.semgrep.scan, deps);
  if (plan.live) return ports.catalog.zap.scan(plan.live.scan, deps);
  if (plan.sonarqube) return ports.catalog.sonarqube.scan(plan.sonarqube.scan, deps);
  if (!plan.offline) return failed(diagnostic('tool_execution_failed', 'error', 'No scan mode is available', plan.adapter));
  const read = await readOfflineReport(plan.offline.reportPath);
  if (!read.ok) {
    return failed(
      read.reason === 'too_large'
        ? diagnostic('resource_limit_exceeded', 'error', 'The offline report exceeds the raw size limit', 'zap')
        : diagnostic('malformed_report', 'error', 'The offline report could not be read', 'zap'),
    );
  }
  return { outcome: 'ok', raw: read.bytes, diagnostics: [], coverageLoss: [], reasons: [] };
}

function targetIdentity(plan: Plan, runner: Runner): FsTargetIdentityReader {
  const semgrep = plan.semgrep;
  if (!semgrep) throw new TypeError('target identity needs a Semgrep plan');
  return new FsTargetIdentityReader({ rootAbs: semgrep.scan.rootAbs, runner, gitTimeoutMs: GIT_TIMEOUT_MS });
}

async function readSources(
  refs: readonly { key: string; path: string; startLine: number; endLine: number }[],
  plan: Plan,
): Promise<{ sources: Map<string, SourceText>; summary: Summary }> {
  const semgrep = plan.semgrep;
  const sources = new Map<string, SourceText>();
  const summary: Summary = {};
  if (!semgrep) return { sources, summary };
  const reader = new FsSourceReader(semgrep.scan.rootAbs, semgrep.scan.targetRel);
  for (const ref of refs) {
    if (sources.has(ref.key)) continue;
    const read = await reader.readLines(ref.path, ref.startLine, ref.endLine);
    if (!read.ok) {
      sources.set(ref.key, read);
      continue;
    }
    // A snippet that cannot be redacted safely is treated as unreadable, never passed on.
    try {
      const result = redactText(read.text, plan.policy);
      sources.set(ref.key, { ok: true, text: result.text, redacted: result.text !== read.text });
      // Counted once per unique reference key: repeated refs `continue` above.
      for (const [id, count] of Object.entries(result.summary)) summary[id] = (summary[id] ?? 0) + count;
    } catch {
      sources.set(ref.key, { ok: false, reason: 'unreadable' });
    }
  }
  return { sources, summary };
}

/** Sums redaction counts by rule id, with keys in a deterministic (code unit) order. */
function mergeSummaries(...parts: Summary[]): Summary {
  const total: Summary = {};
  for (const part of parts) for (const [id, count] of Object.entries(part)) total[id] = (total[id] ?? 0) + count;
  return Object.fromEntries(Object.entries(total).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

function normalizedTarget(plan: Plan, first: Identity | null): NormalizedDocument['target'] {
  if (first === null) {
    return plan.assertedRevision === null
      ? { kind: 'http_origin', origin: plan.targetOrigin ?? '' }
      : { kind: 'http_origin', origin: plan.targetOrigin ?? '', asserted_revision: plan.assertedRevision };
  }
  if (first.kind === 'git') {
    return { kind: 'git', relative_path: first.relative_path, revision: first.revision, dirty: first.dirty, content_digest: first.content_digest };
  }
  return { kind: 'directory', relative_path: first.relative_path, content_digest: first.content_digest };
}
