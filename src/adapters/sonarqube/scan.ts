import type { Deps, RawDiagnostic, ScanOutput, SonarQubeScanContext } from '../../contracts/adapter.js';
import type { DiagnosticCode, JsonValue } from '../../contracts/enums.js';
import { RAW_JSON_MAX_BYTES, SONARQUBE_PAGE_SIZE } from '../../contracts/limits.js';
import type { HttpResult } from '../../contracts/ports.js';
import type { SensitiveString } from '../../contracts/sensitive.js';
import { canonicalJson } from '../../core/fingerprints/index.js';

export const SONARQUBE_REQUEST_TIMEOUT_MS = 30_000;
const ISSUES_ENDPOINT = '/api/issues/search';
const ISSUE_TYPES = 'BUG,VULNERABILITY';

export type SonarQubeCall =
  | { kind: 'ok'; json: Record<string, JsonValue>; bytes: number }
  | { kind: 'bad_key' }
  | { kind: 'closed' }
  | { kind: 'unreachable' }
  | { kind: 'too_large' }
  | { kind: 'error' };

function decodeObject(body: Uint8Array): Record<string, JsonValue> | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(body));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, JsonValue>) : null;
  } catch {
    return null;
  }
}

export function classify(r: HttpResult): SonarQubeCall {
  if (r.kind === 'closed') return { kind: 'closed' };
  if (r.kind === 'timeout') return { kind: 'unreachable' };
  if (r.kind !== 'response') return { kind: 'unreachable' };
  if (r.truncated) return { kind: 'too_large' };
  if (r.body.byteLength === 0) return { kind: 'closed' };
  const json = decodeObject(r.body);
  if (r.status === 401 || r.status === 403) return { kind: 'bad_key' };
  if (r.status >= 200 && r.status < 300) return json ? { kind: 'ok', json, bytes: r.body.byteLength } : { kind: 'error' };
  return { kind: 'error' };
}

async function sonarQubeGet(
  deps: Deps,
  apiUrl: string,
  apiKey: SensitiveString,
  params: Record<string, string>,
  timeoutMs: number,
): Promise<SonarQubeCall> {
  const query = new URLSearchParams(params).toString();
  const url = `${apiUrl.replace(/\/+$/, '')}${ISSUES_ENDPOINT}${query === '' ? '' : `?${query}`}`;
  const r = await deps.http.request({
    url,
    headers: { Accept: 'application/json' },
    sensitiveHeaders: { Authorization: apiKey },
    timeoutMs,
    maxBytes: RAW_JSON_MAX_BYTES,
  });
  return classify(r);
}

function diag(code: DiagnosticCode, level: RawDiagnostic['level'], message: string): RawDiagnostic {
  return { code, level, tool: 'sonarqube', message };
}

function failed(d: RawDiagnostic): ScanOutput {
  return { outcome: 'failed', raw: null, diagnostics: [d], coverageLoss: [], reasons: [] };
}

export async function sonarQubeScan(ctx: SonarQubeScanContext, deps: Deps): Promise<ScanOutput> {
  const timeoutMs = ctx.timeoutSeconds * 1_000;
  const allIssues: JsonValue[] = [];
  let totalExpected: number | null = null;
  let bytesSoFar = 0;
  let page = 1;
  const coverageLoss: RawDiagnostic[] = [];

  for (;;) {
    const params: Record<string, string> = {
      componentKeys: ctx.projectKey,
      types: ISSUE_TYPES,
      resolved: 'false',
      p: String(page),
      ps: String(SONARQUBE_PAGE_SIZE),
    };

    const r = await sonarQubeGet(deps, ctx.apiUrl, ctx.apiKey, params, timeoutMs);

    switch (r.kind) {
      case 'bad_key':
        return failed(diag('bad_api_key', 'error', 'SonarQube rejected the API key'));
      case 'closed':
      case 'unreachable':
        return { outcome: 'unavailable', raw: null, diagnostics: [diag('sonarqube_unreachable_or_rejected', 'error', 'SonarQube is unreachable or rejected the connection')], coverageLoss: [], reasons: [] };
      case 'too_large':
      case 'error':
        return failed(diag('tool_execution_failed', 'error', 'SonarQube API request failed'));
      case 'ok':
        break;
    }

    const rawIssues = r.json['issues'];
    if (!Array.isArray(rawIssues)) return failed(diag('tool_execution_failed', 'error', 'SonarQube response missing issues array'));

    const paging = r.json['paging'];
    if (totalExpected === null) {
      if (typeof paging === 'object' && paging !== null && !Array.isArray(paging)) {
        const total = (paging as Record<string, JsonValue>)['total'];
        if (typeof total === 'number') totalExpected = total;
      }
      if (totalExpected === null) {
        const total = r.json['total'];
        if (typeof total === 'number') totalExpected = total;
      }
      if (totalExpected === null) return failed(diag('tool_execution_failed', 'error', 'SonarQube response missing total count'));
    }

    bytesSoFar += r.bytes;
    if (bytesSoFar > RAW_JSON_MAX_BYTES) {
      coverageLoss.push(diag('resource_limit_exceeded', 'warn', 'SonarQube response exceeds the raw size limit; issues were truncated'));
      break;
    }

    for (const issue of rawIssues) allIssues.push(issue);

    if (allIssues.length >= totalExpected || rawIssues.length < SONARQUBE_PAGE_SIZE) break;
    page++;
  }

  const doc = canonicalJson({ issues: allIssues, total: totalExpected ?? allIssues.length, projectKey: ctx.projectKey });
  const raw = new TextEncoder().encode(doc);

  return { outcome: 'ok', raw, diagnostics: [], coverageLoss, reasons: [] };
}
