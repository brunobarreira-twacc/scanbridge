import assert from 'node:assert/strict';
import { test } from 'node:test';
import { zapProbe } from '../../../../src/adapters/zap/probe.js';
import type { ZapProbeContext } from '../../../../src/contracts/adapter.js';
import { SensitiveString } from '../../../../src/contracts/sensitive.js';
import { API, CANARY, FakeHttp, P, depsWith, json } from './fake-deps.js';

// Only apiUrl and apiKey: no target origin, scan id, session mode or timeouts.
const ctx = (): ZapProbeContext => ({ producer: 'zap', apiUrl: API, apiKey: new SensitiveString(CANARY) });

test('probe success: one keyed GET of the version endpoint, no query', async () => {
  const c = ctx();
  const http = new FakeHttp({ [P.version]: json({ version: '2.15.0' }) });
  const r = await zapProbe(c, depsWith(http));
  assert.deepEqual(r, { status: 'ready', version: '2.15.0', diagnostics: [] });
  assert.equal(http.calls.length, 1);
  assert.equal(http.calls[0]!.url, `${API}${P.version}`);
  assert.strictEqual(http.calls[0]!.sensitiveHeaders?.['X-ZAP-API-Key'], c.apiKey);
});

test('probe: a closed response gives zap_unreachable_or_rejected', async () => {
  const r = await zapProbe(ctx(), depsWith(new FakeHttp({ [P.version]: { kind: 'closed' } })));
  assert.equal(r.status, 'unavailable');
  assert.equal(r.version, null);
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['zap_unreachable_or_rejected']);
});

test('probe: an empty body is treated like a closed response', async () => {
  const empty = { kind: 'response', status: 200, body: new Uint8Array(), truncated: false } as const;
  const r = await zapProbe(ctx(), depsWith(new FakeHttp({ [P.version]: empty })));
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['zap_unreachable_or_rejected']);
});

test('probe: timeout and transport error give tool_unavailable', async () => {
  for (const result of [{ kind: 'timeout' }, { kind: 'error', code: 'ECONNREFUSED' }] as const) {
    const r = await zapProbe(ctx(), depsWith(new FakeHttp({ [P.version]: result })));
    assert.equal(r.status, 'unavailable');
    assert.deepEqual(r.diagnostics.map((d) => d.code), ['tool_unavailable']);
  }
});

test('probe: a structured bad key rejection gives bad_api_key', async () => {
  const r = await zapProbe(ctx(), depsWith(new FakeHttp({ [P.version]: json({ code: 'bad_api_key' }, 400) })));
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['bad_api_key']);
});

test('probe: the canary key never appears in the URL, headers, or result', async () => {
  const http = new FakeHttp({ [P.version]: { kind: 'closed' } });
  const r = await zapProbe(ctx(), depsWith(http));
  const seen = JSON.stringify([http.calls.map((c) => [c.url, c.headers]), r]);
  assert.ok(!seen.includes(CANARY));
});
