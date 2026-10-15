import type { Deps, ProbeResult, RawDiagnostic, ZapProbeContext } from '../../contracts/adapter.js';
import type { DiagnosticCode } from '../../contracts/enums.js';
import { zapGet } from './scan.js';

// [verify] V9: no probe timeout exists in limits.ts; revisited with real fixtures.
const PROBE_TIMEOUT_MS = 5_000;
const PROBE_MAX_BYTES = 64 * 1024;

function unavailable(code: DiagnosticCode, message: string): ProbeResult {
  const d: RawDiagnostic = { code, level: 'error', tool: 'zap', message };
  return { status: 'unavailable', version: null, diagnostics: [d] };
}

/** Exactly one keyed `GET /JSON/core/view/version/`; uses only the API URL and key. */
export async function zapProbe(ctx: ZapProbeContext, deps: Deps): Promise<ProbeResult> {
  const r = await zapGet(deps, ctx.apiUrl, ctx.apiKey, 'version', {}, { timeoutMs: PROBE_TIMEOUT_MS, maxBytes: PROBE_MAX_BYTES });
  switch (r.kind) {
    case 'ok': {
      const version = r.json['version'];
      return { status: 'ready', version: typeof version === 'string' && version !== '' ? version : null, diagnostics: [] };
    }
    case 'bad_key':
      return unavailable('bad_api_key', 'ZAP rejected the API key');
    case 'closed':
      return unavailable('zap_unreachable_or_rejected', 'ZAP closed the connection or returned an empty response');
    default:
      return unavailable('tool_unavailable', 'ZAP version request did not complete');
  }
}
