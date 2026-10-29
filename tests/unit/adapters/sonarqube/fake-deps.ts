import type { Deps, SonarQubeScanContext } from '../../../../src/contracts/adapter.js';
import type { Clock, HttpClient, HttpResult, Runner } from '../../../../src/contracts/ports.js';
import { SensitiveString } from '../../../../src/contracts/sensitive.js';

export const CANARY = 'canary-sq-token-7f3a9c1e';
export const API = 'https://sonarqube.example.test';
export const PROJECT_KEY = 'my-project';

export type Call = { url: string; path: string; query: URLSearchParams; headers: Record<string, string>; sensitiveHeaders?: Record<string, SensitiveString> };
export type Responder = HttpResult | ((call: Call, n: number) => HttpResult);

export function json(body: unknown, status = 200): HttpResult {
  return { kind: 'response', status, body: new TextEncoder().encode(JSON.stringify(body)), truncated: false };
}

export function text(body: string, status = 200): HttpResult {
  return { kind: 'response', status, body: new TextEncoder().encode(body), truncated: false };
}

export class FakeHttp implements HttpClient {
  readonly calls: Call[] = [];
  private readonly counts = new Map<string, number>();

  constructor(private readonly routes: Record<string, Responder | Responder[]>) {}

  async request(r: Parameters<HttpClient['request']>[0]): Promise<HttpResult> {
    const u = new URL(r.url);
    const call: Call = { url: r.url, path: u.pathname, query: u.searchParams, headers: r.headers, sensitiveHeaders: r.sensitiveHeaders };
    this.calls.push(call);
    const n = this.counts.get(u.pathname) ?? 0;
    this.counts.set(u.pathname, n + 1);
    const route = this.routes[u.pathname];
    if (route === undefined) throw new Error(`unscripted request: ${u.pathname}`);
    const pick = Array.isArray(route) ? route[Math.min(n, route.length - 1)]! : route;
    return typeof pick === 'function' ? pick(call, n) : pick;
  }

  paths(): string[] {
    return this.calls.map((c) => c.path);
  }
}

const noRunner: Runner = {
  run: async () => {
    throw new Error('runner is not used by the SonarQube adapter');
  },
};

const noClock: Clock = {
  now: () => new Date(0),
  sleep: async () => {},
};

export function depsWith(http: HttpClient): Deps {
  return { runner: noRunner, http, clock: noClock };
}

export function scanCtx(over: Partial<SonarQubeScanContext> = {}): SonarQubeScanContext {
  return {
    producer: 'sonarqube',
    apiUrl: API,
    apiKey: new SensitiveString(CANARY),
    projectKey: PROJECT_KEY,
    timeoutSeconds: 60,
    ...over,
  };
}

export const VERSION_PATH = '/api/server/version';
export const ISSUES_PATH = '/api/issues/search';

export function issuesPage(issues: unknown[], total: number): HttpResult {
  return json({ paging: { total, pageIndex: 1, pageSize: 500 }, issues });
}

export function issue(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    key: 'AX123',
    rule: 'javasecurity:S3649',
    component: `${PROJECT_KEY}:src/App.java`,
    type: 'VULNERABILITY',
    message: 'SQL injection.',
    impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }],
    ...over,
  };
}
