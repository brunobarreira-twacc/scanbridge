import { SensitiveString } from '../contracts/sensitive.js';
import type { Config, Env } from './types.js';

export type SonarQubeProblem = {
  source: 'env';
  code: 'tool_unavailable';
  message: string;
};

type SonarQubeSection = Config['tools']['sonarqube'];

/** Resolves the three required env vars for a live SonarQube scan. */
export function resolveSonarQubeInputs({ config, env }: { config: Config; env: Env }): {
  apiUrl: string | null;
  apiKey: SensitiveString | null;
  projectKey: string | null;
  problems: SonarQubeProblem[];
} {
  const problems: SonarQubeProblem[] = [];
  const sq = config.tools.sonarqube;
  const apiUrl = readApiUrl(sq, env, problems);
  const apiKey = readApiKey(sq, env, problems);
  const projectKey = readProjectKey(sq, env, problems);
  return { apiUrl, apiKey, projectKey, problems };
}

function readApiUrl(sq: SonarQubeSection, env: Env, problems: SonarQubeProblem[]): string | null {
  const raw = env[sq.apiUrlEnv];
  if (raw === undefined || raw === '') {
    problems.push(envProblem(`${sq.apiUrlEnv} is not set`));
    return null;
  }
  if (!isHttpUrl(raw)) {
    problems.push(envProblem(`${sq.apiUrlEnv} must be a valid http(s) URL without user information`));
    return null;
  }
  return raw;
}

function readApiKey(sq: SonarQubeSection, env: Env, problems: SonarQubeProblem[]): SensitiveString | null {
  const raw = env[sq.apiKeyEnv];
  if (raw === undefined || raw === '') {
    problems.push(envProblem(`${sq.apiKeyEnv} is not set`));
    return null;
  }
  // The full Authorization header value is stored so the HTTP client sends it verbatim.
  return new SensitiveString(`Bearer ${raw}`);
}

function readProjectKey(sq: SonarQubeSection, env: Env, problems: SonarQubeProblem[]): string | null {
  const raw = env[sq.projectKeyEnv];
  if (raw === undefined || raw === '') {
    problems.push(envProblem(`${sq.projectKeyEnv} is not set`));
    return null;
  }
  return raw;
}

function envProblem(message: string): SonarQubeProblem {
  return { source: 'env', code: 'tool_unavailable', message };
}

/** Accepts any http(s) URL without user information. SonarQube servers are not restricted to loopback. */
function isHttpUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  return url.username === '' && url.password === '';
}
