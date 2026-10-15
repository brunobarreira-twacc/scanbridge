import type { Deps, RawDiagnostic, ScanOutput, ZapLiveScanContext } from '../../contracts/adapter.js';
import type { DiagnosticCode, JsonValue } from '../../contracts/enums.js';
import { RAW_JSON_MAX_BYTES, ZAP_ALERTS_PAGE_SIZE } from '../../contracts/limits.js';
import type { HttpResult } from '../../contracts/ports.js';
import type { SensitiveString } from '../../contracts/sensitive.js';
import { canonicalJson, type CanonicalJson } from '../../core/fingerprints/index.js';

// [verify] V3: every path and parameter name below is read from ZAP's API source and is not asserted
// against a running ZAP. They live in this one table so a correction touches one place.
export const ZAP_API = {
  version: { path: '/JSON/core/view/version/', params: [] },
  newSession: { path: '/JSON/core/action/newSession/', params: [] },
  numberOfAlerts: { path: '/JSON/alert/view/numberOfAlerts/', params: ['baseurl'] },
  newContext: { path: '/JSON/context/action/newContext/', params: ['contextName'] },
  includeInContext: { path: '/JSON/context/action/includeInContext/', params: ['contextName', 'regex'] },
  setContextInScope: { path: '/JSON/context/action/setContextInScope/', params: ['contextName', 'booleanInScope'] },
  spiderScan: { path: '/JSON/spider/action/scan/', params: ['url', 'contextName'] },
  spiderStatus: { path: '/JSON/spider/view/status/', params: ['scanId'] },
  spiderStop: { path: '/JSON/spider/action/stop/', params: ['scanId'] },
  spiderResults: { path: '/JSON/spider/view/results/', params: ['scanId'] },
  recordsToScan: { path: '/JSON/pscan/view/recordsToScan/', params: [] },
  alerts: { path: '/JSON/alert/view/alerts/', params: ['baseurl', 'start', 'count'] },
} as const;
export type ZapEndpoint = keyof typeof ZAP_API;

// [verify] V9: no limit exists for these in limits.ts; revisited with real fixtures.
export const ZAP_REQUEST_TIMEOUT_MS = 30_000;
export const ZAP_POLL_INTERVAL_MS = 1_000;
const API_KEY_HEADER = 'X-ZAP-API-Key';

export type ZapCall =
  | { kind: 'ok'; json: { [key: string]: JsonValue }; bytes: number }
  | { kind: 'bad_key' }
  | { kind: 'closed' }
  | { kind: 'unreachable' }
  | { kind: 'too_large' }
  | { kind: 'error' };

function decodeObject(body: Uint8Array): { [key: string]: JsonValue } | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(body));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as { [key: string]: JsonValue }) : null;
  } catch {
    return null;
  }
}

/** Classifies an HTTP result. Redirects are not followed by the client, so a 3xx is an error here. */
export function classify(r: HttpResult): ZapCall {
  if (r.kind === 'closed') return { kind: 'closed' };
  if (r.kind !== 'response') return { kind: 'unreachable' };
  if (r.truncated) return { kind: 'too_large' };
  if (r.body.byteLength === 0) return { kind: 'closed' };
  const json = decodeObject(r.body);
  if (r.status >= 200 && r.status < 300) return json ? { kind: 'ok', json, bytes: r.body.byteLength } : { kind: 'error' };
  return json?.['code'] === 'bad_api_key' ? { kind: 'bad_key' } : { kind: 'error' };
}

/** The key is passed as the very `SensitiveString` object from the context and is never revealed here. */
export async function zapGet(
  deps: Deps,
  apiUrl: string,
  apiKey: SensitiveString,
  endpoint: ZapEndpoint,
  params: Readonly<Record<string, string>>,
  o: { timeoutMs: number; maxBytes: number },
): Promise<ZapCall> {
  const query = new URLSearchParams(params).toString();
  const url = `${apiUrl.replace(/\/+$/, '')}${ZAP_API[endpoint].path}${query === '' ? '' : `?${query}`}`;
  const r = await deps.http.request({
    url,
    headers: { Accept: 'application/json' },
    sensitiveHeaders: { [API_KEY_HEADER]: apiKey },
    timeoutMs: o.timeoutMs,
    maxBytes: o.maxBytes,
  });
  return classify(r);
}

function diag(code: DiagnosticCode, level: RawDiagnostic['level'], message: string): RawDiagnostic {
  return { code, level, tool: 'zap', message };
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Anchored, escaped include regex for exactly one origin (not user supplied). */
export function originRegex(origin: string): string {
  return `^${escapeRegex(origin.replace(/\/+$/, ''))}(?:[/?#].*)?$`;
}

function inOrigin(url: unknown, origin: string): boolean {
  if (typeof url !== 'string') return false;
  try {
    return new URL(url).origin === new URL(origin).origin;
  } catch {
    return false;
  }
}

class Abort extends Error {
  constructor(readonly out: ScanOutput) {
    super('zap scan aborted');
  }
}

function result(outcome: ScanOutput['outcome'], diagnostics: RawDiagnostic[], coverageLoss: RawDiagnostic[] = []): ScanOutput {
  return { outcome, raw: null, diagnostics, coverageLoss, reasons: [] };
}

function executionFailed(message: string): Abort {
  return new Abort(result('failed', [diag('tool_execution_failed', 'error', message)]));
}

export async function zapScan(ctx: ZapLiveScanContext, deps: Deps): Promise<ScanOutput> {
  try {
    return await run(ctx, deps);
  } catch (err) {
    if (err instanceof Abort) return err.out;
    throw err;
  }
}

async function run(ctx: ZapLiveScanContext, deps: Deps): Promise<ScanOutput> {
  const origin = ctx.targetOrigin;
  const coverageLoss: RawDiagnostic[] = [];
  const get = (endpoint: ZapEndpoint, params: Record<string, string> = {}, maxBytes = RAW_JSON_MAX_BYTES) =>
    zapGet(deps, ctx.apiUrl, ctx.apiKey, endpoint, params, { timeoutMs: ZAP_REQUEST_TIMEOUT_MS, maxBytes });

  /** A call whose failure ends the scan as `failed` (`tool_execution_failed`). */
  const need = async (what: string, endpoint: ZapEndpoint, params: Record<string, string> = {}) => {
    const r = await get(endpoint, params);
    if (r.kind !== 'ok') throw executionFailed(`ZAP request failed: ${what}`);
    return r.json;
  };
  const alertCount = async (what: string): Promise<number> => {
    const n = Number((await need(what, 'numberOfAlerts', { baseurl: origin }))['numberOfAlerts']);
    if (!Number.isInteger(n) || n < 0) throw executionFailed(`ZAP returned an invalid alert count: ${what}`);
    return n;
  };

  // Step 1 and 2: the first keyed action decides bad key / unreachable, then session state.
  const first = ctx.sessionMode === 'reset' ? await get('newSession') : await get('numberOfAlerts', { baseurl: origin });
  if (first.kind === 'bad_key') {
    throw new Abort(result('unavailable', [diag('bad_api_key', 'error', 'ZAP rejected the API key')]));
  }
  if (first.kind === 'closed' || first.kind === 'unreachable' || (first.kind === 'error' && ctx.sessionMode === 'require_clean')) {
    throw new Abort(result('unavailable', [diag('zap_unreachable_or_rejected', 'error', 'ZAP did not accept the first API request')]));
  }
  if (first.kind !== 'ok') {
    throw executionFailed(ctx.sessionMode === 'reset' ? 'ZAP could not reset the session' : 'ZAP returned an unusable response');
  }
  if (ctx.sessionMode === 'require_clean') {
    const n = Number(first.json['numberOfAlerts']);
    if (!Number.isInteger(n) || n < 0) throw executionFailed('ZAP returned an invalid alert count');
    if (n !== 0) {
      throw new Abort(result('failed', [diag('zap_session_not_clean', 'error', 'ZAP session already holds alerts for the target origin')]));
    }
  }

  // Step 3: context and spider.
  const contextName = `scanbridge-${ctx.scanId}`;
  await need('create context', 'newContext', { contextName });
  await need('include origin in context', 'includeInContext', { contextName, regex: originRegex(origin) });
  await need('set context in scope', 'setContextInScope', { contextName, booleanInScope: 'true' });
  const started = await need('start spider', 'spiderScan', { url: origin, contextName });
  const spiderId = started['scan'];
  if (typeof spiderId !== 'string' && typeof spiderId !== 'number') throw executionFailed('ZAP did not return a spider scan id');
  const scanId = String(spiderId);

  // Step 4: deadlines.
  const waitFor = async (timeoutSeconds: number, done: () => Promise<boolean>): Promise<boolean> => {
    const deadline = deps.clock.now().getTime() + timeoutSeconds * 1000;
    for (;;) {
      if (await done()) return true;
      if (deps.clock.now().getTime() >= deadline) return false;
      await deps.clock.sleep(ZAP_POLL_INTERVAL_MS);
    }
  };
  const spiderDone = await waitFor(ctx.spiderTimeoutSeconds, async () => {
    const status = (await need('read spider status', 'spiderStatus', { scanId }))['status'];
    return String(status) === '100';
  });
  if (!spiderDone) {
    // The result of the stop request does not change the outcome: the deadline was already hit.
    await get('spiderStop', { scanId });
    coverageLoss.push(diag('tool_timeout', 'warn', 'ZAP spider did not finish before its deadline and was stopped'));
  }
  const passiveDone = await waitFor(ctx.passiveTimeoutSeconds, async () => {
    return String((await need('read passive queue', 'recordsToScan'))['recordsToScan']) === '0';
  });
  if (!passiveDone) {
    coverageLoss.push(diag('tool_timeout', 'warn', 'ZAP passive scan queue did not drain before its deadline'));
  }

  // Step 5: discovered URLs.
  const urls = (await need('read spider results', 'spiderResults', { scanId }))['results'];
  if (!Array.isArray(urls)) throw executionFailed('ZAP returned unusable spider results');
  if (!urls.some((u) => inOrigin(u, origin))) {
    coverageLoss.push(diag('no_urls_discovered', 'warn', 'The spider discovered no URL inside the target origin'));
  }

  // Step 6: alert pages.
  const before = await alertCount('count before paging');
  const alerts: JsonValue[] = [];
  let total = 0;
  for (let start = 0; ; start += ZAP_ALERTS_PAGE_SIZE) {
    const page = await get('alerts', { baseurl: origin, start: String(start), count: String(ZAP_ALERTS_PAGE_SIZE) }, RAW_JSON_MAX_BYTES - total);
    if (page.kind === 'too_large') {
      throw new Abort(result('failed', [diag('resource_limit_exceeded', 'error', 'ZAP alert pages exceeded the raw size limit')]));
    }
    const items = page.kind === 'ok' ? page.json['alerts'] : undefined;
    if (page.kind !== 'ok' || !Array.isArray(items)) {
      if (alerts.length === 0) throw executionFailed('ZAP alert page could not be read');
      coverageLoss.push(diag('partial_coverage', 'warn', 'A ZAP alert page could not be read; collected alerts are incomplete'));
      break;
    }
    total += page.bytes;
    if (total > RAW_JSON_MAX_BYTES) {
      throw new Abort(result('failed', [diag('resource_limit_exceeded', 'error', 'ZAP alert pages exceeded the raw size limit')]));
    }
    alerts.push(...items);
    if (items.length < ZAP_ALERTS_PAGE_SIZE) break;
  }
  try {
    const after = await alertCount('count after paging');
    if (after !== before) {
      coverageLoss.push(diag('partial_coverage', 'warn', 'The ZAP alert count changed while the alerts were being read'));
    }
  } catch (err) {
    // Evidence is already in hand: an unreadable second count is lost coverage, not a failed scan.
    if (!(err instanceof Abort)) throw err;
    coverageLoss.push(diag('partial_coverage', 'warn', 'The ZAP alert count could not be re-read after paging'));
  }

  // Step 7: producer-shaped document, page order and duplicates kept.
  let raw: Uint8Array;
  try {
    raw = new TextEncoder().encode(canonicalJson({ alerts } as CanonicalJson));
  } catch {
    throw executionFailed('ZAP alerts could not be serialized canonically');
  }
  return { outcome: 'ok', raw, diagnostics: [], coverageLoss, reasons: [] };
}
