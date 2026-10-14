import type { Deps, ProbeResult, SemgrepProbeContext } from '../../contracts/adapter.js';
import { RAW_JSON_MAX_BYTES, SEMGREP_PROCESS_TIMEOUT_MIN } from '../../contracts/limits.js';

// No probe-specific timeout exists in limits.ts; the shortest process timeout is used. Gap reported in the handoff.
const PROBE_TIMEOUT_MS = SEMGREP_PROCESS_TIMEOUT_MIN * 1000;

/** Lenient: the first version-looking token in stdout, or null. */
function parseVersion(stdout: Uint8Array): string | null {
  const match = /\b\d+\.\d+(?:\.\d+)*(?:[-+][\w.-]+)?/.exec(new TextDecoder().decode(stdout));
  return match ? match[0] : null;
}

export async function probe(_ctx: SemgrepProbeContext, deps: Deps): Promise<ProbeResult> {
  // The probe has no root, so the cwd is the process default ('.').
  const r = await deps.runner.run('semgrep', ['--version'], {
    cwd: '.',
    timeoutMs: PROBE_TIMEOUT_MS,
    maxStdoutBytes: RAW_JSON_MAX_BYTES,
  });
  if (r.spawnFailed || r.timedOut || r.exitCode !== 0) {
    return {
      status: 'unavailable',
      version: null,
      diagnostics: [{ code: 'tool_unavailable', level: 'error', tool: 'semgrep', message: 'semgrep --version did not complete' }],
    };
  }
  return { status: 'ready', version: parseVersion(r.stdout), diagnostics: [] };
}
