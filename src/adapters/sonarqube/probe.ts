import type { Deps, ProbeResult, RawDiagnostic, SonarQubeProbeContext } from '../../contracts/adapter.js';
import type { DiagnosticCode } from '../../contracts/enums.js';

const PROBE_TIMEOUT_MS = 5_000;
const PROBE_MAX_BYTES = 64 * 1024;

function unavailable(code: DiagnosticCode, message: string): ProbeResult {
  const d: RawDiagnostic = { code, level: 'error', tool: 'sonarqube', message };
  return { status: 'unavailable', version: null, diagnostics: [d] };
}

/** GET /api/server/version — plain-text response, e.g. "10.6.0.92116". */
export async function sonarQubeProbe(ctx: SonarQubeProbeContext, deps: Deps): Promise<ProbeResult> {
  const url = `${ctx.apiUrl.replace(/\/+$/, '')}/api/server/version`;
  const r = await deps.http.request({
    url,
    headers: { Accept: 'text/plain' },
    sensitiveHeaders: { Authorization: ctx.apiKey },
    timeoutMs: PROBE_TIMEOUT_MS,
    maxBytes: PROBE_MAX_BYTES,
  });

  if (r.kind === 'timeout') return unavailable('tool_unavailable', 'SonarQube version request timed out');
  if (r.kind !== 'response') return unavailable('sonarqube_unreachable_or_rejected', 'SonarQube is unreachable or rejected the connection');
  if (r.status === 401 || r.status === 403) return unavailable('bad_api_key', 'SonarQube rejected the API key');
  if (r.status < 200 || r.status >= 300) return unavailable('sonarqube_unreachable_or_rejected', 'SonarQube returned an unexpected status');

  const version = new TextDecoder().decode(r.body).trim();
  return { status: 'ready', version: version !== '' ? version : null, diagnostics: [] };
}
