import { SensitiveString } from '../contracts/sensitive.js';
import { normalizeUrl } from '../core/fingerprints/index.js';
import type { Config, Env } from './types.js';

/**
 * Problems name the variable or flag, never its value. `env` problems are readiness failures (exit 2,
 * `tool_unavailable`); `flag` problems are usage errors (exit 1).
 */
export type ZapProblem = {
  source: 'env' | 'flag';
  code: 'tool_unavailable' | 'usage_error';
  message: string;
};

export type ZapFlags = { targetUrl?: string };

type ZapSection = Config['tools']['zap'];

/** Doctor: API URL and API key only. Never reads `target_url_env`. */
export function resolveZapDoctorInputs({ config, env }: { config: Config; env: Env }): {
  apiUrl: string | null;
  apiKey: SensitiveString | null;
  apiKeyPresent: boolean;
  problems: ZapProblem[];
} {
  const problems: ZapProblem[] = [];
  const apiUrl = readApiUrl(config.tools.zap, env, problems);
  const { apiKey, apiKeyPresent } = readApiKey(config.tools.zap, env, problems);
  return { apiUrl, apiKey, apiKeyPresent, problems };
}

/** Live scan: API URL, API key and target URL. The flag wins over `target_url_env`. */
export function resolveZapLiveInputs({ config, env, flags }: { config: Config; env: Env; flags: ZapFlags }): {
  apiUrl: string | null;
  apiKey: SensitiveString | null;
  targetUrl: string | null;
  targetUrlOverridden: boolean;
  problems: ZapProblem[];
} {
  const problems: ZapProblem[] = [];
  const apiUrl = readApiUrl(config.tools.zap, env, problems);
  const { apiKey } = readApiKey(config.tools.zap, env, problems);
  const { targetUrl, targetUrlOverridden } = readTargetUrl(config.tools.zap, env, flags, problems);
  return { apiUrl, apiKey, targetUrl, targetUrlOverridden, problems };
}

/** Offline import: target URL only. Never reads `api_url_env` or `api_key_env`. */
export function resolveZapOfflineInputs({ config, env, flags }: { config: Config; env: Env; flags: ZapFlags }): {
  targetUrl: string | null;
  targetUrlOverridden: boolean;
  problems: ZapProblem[];
} {
  const problems: ZapProblem[] = [];
  const { targetUrl, targetUrlOverridden } = readTargetUrl(config.tools.zap, env, flags, problems);
  return { targetUrl, targetUrlOverridden, problems };
}

function readApiUrl(zap: ZapSection, env: Env, problems: ZapProblem[]): string | null {
  const raw = env[zap.apiUrlEnv];
  if (raw === undefined || raw === '') {
    problems.push(envProblem(`${zap.apiUrlEnv} is not set`));
    return null;
  }
  if (!isLoopbackHttpUrl(raw)) {
    problems.push(envProblem(`${zap.apiUrlEnv} must be a loopback http(s) URL without user information`));
    return null;
  }
  return raw;
}

function readApiKey(
  zap: ZapSection,
  env: Env,
  problems: ZapProblem[],
): { apiKey: SensitiveString | null; apiKeyPresent: boolean } {
  const raw = env[zap.apiKeyEnv];
  if (raw === undefined || raw === '') {
    problems.push(envProblem(`${zap.apiKeyEnv} is not set`));
    return { apiKey: null, apiKeyPresent: false };
  }
  return { apiKey: new SensitiveString(raw), apiKeyPresent: true };
}

function readTargetUrl(
  zap: ZapSection,
  env: Env,
  flags: ZapFlags,
  problems: ZapProblem[],
): { targetUrl: string | null; targetUrlOverridden: boolean } {
  if (flags.targetUrl !== undefined) {
    const problem = targetProblem(flags.targetUrl, zap.allowedTargetOrigins, 'flag', '--target-url');
    if (problem === null) return { targetUrl: flags.targetUrl, targetUrlOverridden: true };
    problems.push(problem);
    return { targetUrl: null, targetUrlOverridden: true };
  }
  const raw = env[zap.targetUrlEnv];
  if (raw === undefined || raw === '') {
    problems.push(envProblem(`${zap.targetUrlEnv} is not set and no --target-url was given`));
    return { targetUrl: null, targetUrlOverridden: false };
  }
  const problem = targetProblem(raw, zap.allowedTargetOrigins, 'env', zap.targetUrlEnv);
  if (problem === null) return { targetUrl: raw, targetUrlOverridden: false };
  problems.push(problem);
  return { targetUrl: null, targetUrlOverridden: false };
}

function targetProblem(url: string, allowedOrigins: readonly string[], source: 'env' | 'flag', label: string): ZapProblem | null {
  const code = source === 'flag' ? 'usage_error' : 'tool_unavailable';
  let origin: string;
  try {
    origin = normalizeUrl(url).origin;
  } catch {
    return { source, code, message: `${label} is not a valid http(s) URL` };
  }
  if (!allowedOrigins.includes(origin)) {
    return { source, code, message: `${label} origin is not listed in allowed_target_origins` };
  }
  return null;
}

function envProblem(message: string): ZapProblem {
  return { source: 'env', code: 'tool_unavailable', message };
}

/** Parse-only check: http(s), no user information, host is localhost, ::1 or 127.0.0.0/8. */
function isLoopbackHttpUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username !== '' || url.password !== '') return false;
  const host = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
  if (host === 'localhost' || host === '::1') return true;
  return /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(host) && host.split('.').every((octet) => Number(octet) <= 255);
}
