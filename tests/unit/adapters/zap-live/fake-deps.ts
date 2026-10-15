import type { Deps, ZapLiveScanContext } from '../../../../src/contracts/adapter.js';
import type { Clock, HttpClient, HttpResult, Runner } from '../../../../src/contracts/ports.js';
import { SensitiveString } from '../../../../src/contracts/sensitive.js';

export const CANARY = 'canary-key-7f3a9c1e';
export const API = 'http://127.0.0.1:8080';
export const ORIGIN = 'http://app.test:3000';

export type Call = { url: string; path: string; query: URLSearchParams; headers: Record<string, string>; sensitiveHeaders?: Record<string, SensitiveString>; maxBytes: number };
export type Responder = HttpResult | ((call: Call, n: number) => HttpResult);

export function json(body: unknown, status = 200): HttpResult {
  return { kind: 'response', status, body: new TextEncoder().encode(JSON.stringify(body)), truncated: false };
}

/** Routes by URL path; each route is a fixed result, a function, or a queue consumed in order (last one repeats). */
export class FakeHttp implements HttpClient {
  readonly calls: Call[] = [];
  private readonly counts = new Map<string, number>();

  constructor(private readonly routes: Record<string, Responder | Responder[]>) {}

  async request(r: Parameters<HttpClient['request']>[0]): Promise<HttpResult> {
    const u = new URL(r.url);
    const call: Call = { url: r.url, path: u.pathname, query: u.searchParams, headers: r.headers, sensitiveHeaders: r.sensitiveHeaders, maxBytes: r.maxBytes };
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

export class FakeClock implements Clock {
  t = 0;
  sleeps: number[] = [];
  now(): Date {
    return new Date(this.t);
  }
  async sleep(ms: number): Promise<void> {
    this.sleeps.push(ms);
    this.t += ms;
  }
}

const noRunner: Runner = {
  run: async () => {
    throw new Error('runner is not used by the ZAP adapter');
  },
};

export function depsWith(http: HttpClient, clock: Clock = new FakeClock()): Deps {
  return { runner: noRunner, http, clock };
}

export function scanCtx(over: Partial<ZapLiveScanContext> = {}): ZapLiveScanContext {
  return {
    producer: 'zap',
    mode: 'live',
    scanId: 'scan-1',
    targetOrigin: ORIGIN,
    apiUrl: API,
    apiKey: new SensitiveString(CANARY),
    sessionMode: 'require_clean',
    spiderTimeoutSeconds: 10,
    passiveTimeoutSeconds: 10,
    ...over,
  };
}

export const P = {
  version: '/JSON/core/view/version/',
  newSession: '/JSON/core/action/newSession/',
  count: '/JSON/alert/view/numberOfAlerts/',
  newContext: '/JSON/context/action/newContext/',
  include: '/JSON/context/action/includeInContext/',
  inScope: '/JSON/context/action/setContextInScope/',
  spiderScan: '/JSON/spider/action/scan/',
  spiderStatus: '/JSON/spider/view/status/',
  spiderStop: '/JSON/spider/action/stop/',
  spiderResults: '/JSON/spider/view/results/',
  passive: '/JSON/pscan/view/recordsToScan/',
  alerts: '/JSON/alert/view/alerts/',
};

export function alert(i: number): Record<string, string> {
  return { pluginId: '10021', url: `${ORIGIN}/p${i}`, alert: `A${i}` };
}

/** A working ZAP; override single routes per test. */
export function happyRoutes(over: Record<string, Responder | Responder[]> = {}): Record<string, Responder | Responder[]> {
  return {
    [P.newSession]: json({ Result: 'OK' }),
    [P.count]: json({ numberOfAlerts: '0' }),
    [P.newContext]: json({ contextId: '1' }),
    [P.include]: json({ Result: 'OK' }),
    [P.inScope]: json({ Result: 'OK' }),
    [P.spiderScan]: json({ scan: '0' }),
    [P.spiderStatus]: json({ status: '100' }),
    [P.spiderStop]: json({ Result: 'OK' }),
    [P.spiderResults]: json({ results: [`${ORIGIN}/`, 'http://other.test/x'] }),
    [P.passive]: json({ recordsToScan: '0' }),
    [P.alerts]: json({ alerts: [] }),
    ...over,
  };
}

export const decode = (b: Uint8Array | null): string => new TextDecoder().decode(b ?? new Uint8Array());
