import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sonarQubeProbe } from '../../../../src/adapters/sonarqube/probe.js';
import type { SonarQubeProbeContext } from '../../../../src/contracts/adapter.js';
import { SensitiveString } from '../../../../src/contracts/sensitive.js';
import { API, CANARY, FakeHttp, VERSION_PATH, depsWith, text, json } from './fake-deps.js';

const ctx = (): SonarQubeProbeContext => ({
  producer: 'sonarqube',
  apiUrl: API,
  apiKey: new SensitiveString(CANARY),
  projectKey: 'my-project',
});

test('probe success: version string returned, status ready', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: text('10.6.0.92116') });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.deepEqual(r, { status: 'ready', version: '10.6.0.92116', diagnostics: [] });
  assert.equal(http.calls.length, 1);
  const call = http.calls[0]!;
  assert.equal(call.path, VERSION_PATH);
  assert.ok(call.sensitiveHeaders?.['Authorization'] instanceof SensitiveString);
});

test('probe success: empty body gives null version, still ready', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: text('') });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'ready');
  assert.equal(r.version, null);
  assert.deepEqual(r.diagnostics, []);
});

test('probe: 401 gives bad_api_key', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: json({ errors: [{ msg: 'Unauthorized' }] }, 401) });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'unavailable');
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['bad_api_key']);
});

test('probe: 403 gives bad_api_key', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: json({ errors: [{ msg: 'Forbidden' }] }, 403) });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'unavailable');
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['bad_api_key']);
});

test('probe: closed connection gives sonarqube_unreachable_or_rejected', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: { kind: 'closed' } });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'unavailable');
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['sonarqube_unreachable_or_rejected']);
});

test('probe: timeout gives tool_unavailable', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: { kind: 'timeout' } });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'unavailable');
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['tool_unavailable']);
});

test('probe: error gives sonarqube_unreachable_or_rejected', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: { kind: 'error', code: 'ECONNREFUSED' } });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'unavailable');
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['sonarqube_unreachable_or_rejected']);
});

test('probe: non-2xx gives sonarqube_unreachable_or_rejected', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: json({ message: 'Service Unavailable' }, 503) });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  assert.equal(r.status, 'unavailable');
  assert.deepEqual(r.diagnostics.map((d) => d.code), ['sonarqube_unreachable_or_rejected']);
});

test('probe: the canary token never appears in the URL or result', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: { kind: 'closed' } });
  const r = await sonarQubeProbe(ctx(), depsWith(http));
  const seen = JSON.stringify([http.calls.map((c) => [c.url, c.headers]), r]);
  assert.ok(!seen.includes(CANARY));
});

test('probe: Authorization header is passed as a SensitiveString, not revealed in URL', async () => {
  const http = new FakeHttp({ [VERSION_PATH]: text('10.0.0') });
  await sonarQubeProbe(ctx(), depsWith(http));
  const call = http.calls[0]!;
  assert.ok(call.sensitiveHeaders?.['Authorization'] instanceof SensitiveString);
  assert.ok(!call.url.includes(CANARY));
  assert.ok(!JSON.stringify(call.headers).includes(CANARY));
});
