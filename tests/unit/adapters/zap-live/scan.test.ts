import assert from 'node:assert/strict';
import { test } from 'node:test';
import { originRegex, zapScan } from '../../../../src/adapters/zap/scan.js';
import { RAW_JSON_MAX_BYTES, ZAP_ALERTS_PAGE_SIZE } from '../../../../src/contracts/limits.js';
import { ORIGIN, CANARY, FakeClock, FakeHttp, P, alert, decode, depsWith, happyRoutes, json, scanCtx } from './fake-deps.js';

const codes = (xs: { code: string }[]): string[] => xs.map((x) => x.code);

test('happy path: request sequence, ok outcome, canonical raw document', async () => {
  const http = new FakeHttp(happyRoutes({ [P.alerts]: json({ alerts: [alert(1), alert(2), alert(1)] }) }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(out.diagnostics, []);
  assert.deepEqual(out.coverageLoss, []);
  assert.deepEqual(out.reasons, []);
  assert.deepEqual(http.paths(), [P.count, P.newContext, P.include, P.inScope, P.spiderScan, P.spiderStatus, P.passive, P.spiderResults, P.count, P.alerts, P.count]);
  const q = (i: number) => http.calls[i]!.query;
  assert.equal(q(0).get('baseurl'), ORIGIN);
  assert.equal(q(1).get('contextName'), 'scanbridge-scan-1');
  assert.equal(q(2).get('regex'), originRegex(ORIGIN));
  assert.equal(q(4).get('url'), ORIGIN);
  assert.equal(q(4).get('contextName'), 'scanbridge-scan-1');
  assert.equal(q(9).get('count'), String(ZAP_ALERTS_PAGE_SIZE));
  assert.equal(q(9).get('start'), '0');
  assert.equal(q(9).get('baseurl'), ORIGIN);
  // Page order and duplicates are kept; keys are sorted (RFC 8785).
  const expected = `{"alerts":[${[1, 2, 1].map((i) => JSON.stringify({ alert: `A${i}`, pluginId: '10021', url: `${ORIGIN}/p${i}` })).join(',')}]}`;
  assert.equal(decode(out.raw), expected);
});

test('paging: full pages are followed in order and duplicates survive', async () => {
  const full = Array.from({ length: ZAP_ALERTS_PAGE_SIZE }, (_, i) => alert(i));
  const http = new FakeHttp(
    happyRoutes({ [P.alerts]: [json({ alerts: full }), json({ alerts: [alert(0), alert(9999)] })] }),
  );
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  const doc = JSON.parse(decode(out.raw)) as { alerts: { alert: string }[] };
  assert.equal(doc.alerts.length, ZAP_ALERTS_PAGE_SIZE + 2);
  assert.equal(doc.alerts[ZAP_ALERTS_PAGE_SIZE]!.alert, 'A0');
  assert.deepEqual(http.calls.filter((c) => c.path === P.alerts).map((c) => c.query.get('start')), ['0', String(ZAP_ALERTS_PAGE_SIZE)]);
});

test('dirty session: failed with zap_session_not_clean and no contact beyond the count', async () => {
  const http = new FakeHttp(happyRoutes({ [P.count]: json({ numberOfAlerts: '3' }) }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.equal(out.raw, null);
  assert.deepEqual(codes(out.diagnostics), ['zap_session_not_clean']);
  assert.deepEqual(http.paths(), [P.count]);
});

test('reset mode: newSession is the first request and no clean check follows', async () => {
  const http = new FakeHttp(happyRoutes({ [P.count]: json({ numberOfAlerts: '3' }) }));
  const out = await zapScan(scanCtx({ sessionMode: 'reset' }), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.equal(http.paths()[0], P.newSession);
  assert.equal(http.paths()[1], P.newContext);
});

test('reset failure: failed before any context or target contact', async () => {
  const http = new FakeHttp(happyRoutes({ [P.newSession]: json({ code: 'internal_error' }, 500) }));
  const out = await zapScan(scanCtx({ sessionMode: 'reset' }), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(codes(out.diagnostics), ['tool_execution_failed']);
  assert.deepEqual(http.paths(), [P.newSession]);
});

test('bad key on the first keyed action: unavailable with bad_api_key', async () => {
  for (const mode of ['require_clean', 'reset'] as const) {
    const first = mode === 'reset' ? P.newSession : P.count;
    const http = new FakeHttp(happyRoutes({ [first]: json({ code: 'bad_api_key', message: 'Bad API key' }, 400) }));
    const out = await zapScan(scanCtx({ sessionMode: mode }), depsWith(http));
    assert.equal(out.outcome, 'unavailable');
    assert.equal(out.raw, null);
    assert.deepEqual(codes(out.diagnostics), ['bad_api_key']);
    assert.equal(http.calls.length, 1);
  }
});

test('closed or empty response on the first keyed action: unavailable with zap_unreachable_or_rejected', async () => {
  const empty = { kind: 'response', status: 200, body: new Uint8Array(), truncated: false } as const;
  for (const result of [{ kind: 'closed' }, empty] as const) {
    const http = new FakeHttp(happyRoutes({ [P.count]: result }));
    const out = await zapScan(scanCtx(), depsWith(http));
    assert.equal(out.outcome, 'unavailable');
    assert.deepEqual(codes(out.diagnostics), ['zap_unreachable_or_rejected']);
  }
});

test('spider deadline: stop request sent and tool_timeout recorded even if ZAP then reports 100', async () => {
  const clock = new FakeClock();
  const http = new FakeHttp(happyRoutes({ [P.spiderStatus]: json({ status: '40' }), [P.alerts]: json({ alerts: [alert(1)] }) }));
  const out = await zapScan(scanCtx({ spiderTimeoutSeconds: 3 }), depsWith(http, clock));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(codes(out.coverageLoss), ['tool_timeout']);
  assert.equal(http.paths().filter((p) => p === P.spiderStop).length, 1);
  assert.equal(http.calls.find((c) => c.path === P.spiderStop)!.query.get('scanId'), '0');
  assert.equal(http.paths().filter((p) => p === P.spiderStatus).length, 4);
  assert.deepEqual(clock.sleeps, [1000, 1000, 1000]);
  assert.ok(out.raw);
});

test('spider deadline that sees 100 at the last poll is not a timeout', async () => {
  const http = new FakeHttp(happyRoutes({ [P.spiderStatus]: [json({ status: '10' }), json({ status: '100' })] }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.deepEqual(out.coverageLoss, []);
  assert.ok(!http.paths().includes(P.spiderStop));
});

test('passive deadline: tool_timeout recorded, scan continues', async () => {
  const http = new FakeHttp(happyRoutes({ [P.passive]: json({ recordsToScan: '12' }) }));
  const out = await zapScan(scanCtx({ passiveTimeoutSeconds: 2 }), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(codes(out.coverageLoss), ['tool_timeout']);
  assert.ok(out.raw);
});

test('zero in-scope URLs: no_urls_discovered', async () => {
  const http = new FakeHttp(happyRoutes({ [P.spiderResults]: json({ results: ['http://other.test/'] }) }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(codes(out.coverageLoss), ['no_urls_discovered']);
});

test('count change while paging: partial_coverage', async () => {
  const http = new FakeHttp(happyRoutes({ [P.count]: [json({ numberOfAlerts: '0' }), json({ numberOfAlerts: '0' }), json({ numberOfAlerts: '1' })], [P.alerts]: json({ alerts: [alert(1)] }) }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(codes(out.coverageLoss), ['partial_coverage']);
});

test('size cap: pages beyond 50 MiB give failed + resource_limit_exceeded', async () => {
  const big = { kind: 'response', status: 200, body: new Uint8Array(10), truncated: true } as const;
  const http = new FakeHttp(happyRoutes({ [P.alerts]: big }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.equal(out.raw, null);
  assert.deepEqual(codes(out.diagnostics), ['resource_limit_exceeded']);
  assert.equal(http.calls.find((c) => c.path === P.alerts)!.maxBytes, RAW_JSON_MAX_BYTES);
});

test('size cap is cumulative: later pages get only the remaining budget', async () => {
  const full = Array.from({ length: ZAP_ALERTS_PAGE_SIZE }, (_, i) => alert(i));
  const http = new FakeHttp(happyRoutes({ [P.alerts]: [json({ alerts: full }), json({ alerts: [] })] }));
  await zapScan(scanCtx(), depsWith(http));
  const [a, b] = http.calls.filter((c) => c.path === P.alerts);
  const firstBytes = new TextEncoder().encode(JSON.stringify({ alerts: full })).byteLength;
  assert.equal(b!.maxBytes, a!.maxBytes - firstBytes);
});

test('API failure before any alerts: failed with tool_execution_failed', async () => {
  for (const route of [P.newContext, P.spiderStatus, P.alerts]) {
    const http = new FakeHttp(happyRoutes({ [route]: json({ code: 'internal_error' }, 500) }));
    const out = await zapScan(scanCtx(), depsWith(http));
    assert.equal(out.outcome, 'failed', route);
    assert.equal(out.raw, null);
    assert.deepEqual(codes(out.diagnostics), ['tool_execution_failed']);
  }
});

test('API failure after evidence: collected alerts returned with partial_coverage', async () => {
  const full = Array.from({ length: ZAP_ALERTS_PAGE_SIZE }, (_, i) => alert(i));
  const http = new FakeHttp(happyRoutes({ [P.alerts]: [json({ alerts: full }), { kind: 'closed' }] }));
  const out = await zapScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(codes(out.coverageLoss), ['partial_coverage']);
  assert.equal((JSON.parse(decode(out.raw)) as { alerts: unknown[] }).alerts.length, ZAP_ALERTS_PAGE_SIZE);
});

test('the key goes only through sensitiveHeaders as the same object; the canary leaks nowhere', async () => {
  const ctx = scanCtx();
  const failing = [
    happyRoutes({ [P.alerts]: json({ alerts: [alert(1)] }) }),
    happyRoutes({ [P.count]: json({ numberOfAlerts: '2' }) }),
    happyRoutes({ [P.spiderStatus]: json({ status: '1' }) }),
    happyRoutes({ [P.newContext]: json({ code: 'bad_api_key' }, 400) }),
  ];
  for (const routes of failing) {
    const http = new FakeHttp(routes);
    const out = await zapScan(ctx, depsWith(http));
    for (const c of http.calls) {
      assert.strictEqual(c.sensitiveHeaders?.['X-ZAP-API-Key'], ctx.apiKey);
      assert.deepEqual(Object.keys(c.sensitiveHeaders ?? {}), ['X-ZAP-API-Key']);
      assert.ok(!c.url.includes(CANARY));
      assert.ok(!JSON.stringify(c.headers).includes(CANARY));
      assert.ok(!/api.?key/i.test(c.url));
    }
    assert.ok(!JSON.stringify(out).includes(CANARY));
    assert.ok(!decode(out.raw).includes(CANARY));
  }
});

test('originRegex is anchored and escapes metacharacters', () => {
  const re = new RegExp(originRegex('http://app.test:3000'));
  assert.ok(re.test('http://app.test:3000'));
  assert.ok(re.test('http://app.test:3000/a?b=1'));
  assert.ok(!re.test('http://appxtest:3000/'));
  assert.ok(!re.test('http://app.test:30001/'));
  assert.ok(!re.test('http://app.test:3000.evil.test/'));
  assert.ok(!re.test('https://x/http://app.test:3000/'));
});
