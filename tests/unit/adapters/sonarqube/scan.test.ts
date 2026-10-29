import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sonarQubeScan } from '../../../../src/adapters/sonarqube/scan.js';
import { RAW_JSON_MAX_BYTES, SONARQUBE_PAGE_SIZE } from '../../../../src/contracts/limits.js';
import { API, CANARY, FakeHttp, ISSUES_PATH, depsWith, issue, issuesPage, scanCtx } from './fake-deps.js';

const decode = (b: Uint8Array | null): string => new TextDecoder().decode(b ?? new Uint8Array());
const codes = (xs: { code: string }[]): string[] => xs.map((x) => x.code);

test('single page success: outcome ok, canonical raw JSON with expected shape', async () => {
  const issues = [issue()];
  const http = new FakeHttp({ [ISSUES_PATH]: issuesPage(issues, 1) });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(out.diagnostics, []);
  assert.deepEqual(out.coverageLoss, []);
  const doc = JSON.parse(decode(out.raw)) as { issues: unknown[]; total: number; projectKey: string };
  assert.equal(doc.total, 1);
  assert.equal(doc.projectKey, 'my-project');
  assert.equal(doc.issues.length, 1);
  assert.equal(http.calls.length, 1);
  const q = http.calls[0]!.query;
  assert.equal(q.get('componentKeys'), 'my-project');
  assert.equal(q.get('types'), 'BUG,VULNERABILITY');
  assert.equal(q.get('resolved'), 'false');
  assert.equal(q.get('p'), '1');
  assert.equal(q.get('ps'), String(SONARQUBE_PAGE_SIZE));
});

test('multi-page pagination: all issues collected', async () => {
  const fullPage = Array.from({ length: SONARQUBE_PAGE_SIZE }, (_, i) => issue({ key: `K${i}` }));
  const extra = [issue({ key: 'Klast' })];
  const total = SONARQUBE_PAGE_SIZE + 1;
  const http = new FakeHttp({
    [ISSUES_PATH]: [
      issuesPage(fullPage, total),
      issuesPage(extra, total),
    ],
  });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  const doc = JSON.parse(decode(out.raw)) as { issues: unknown[]; total: number };
  assert.equal(doc.issues.length, total);
  assert.equal(doc.total, total);
  assert.equal(http.calls.length, 2);
  assert.equal(http.calls[1]!.query.get('p'), '2');
});

test('no more pages when issues.length < page size', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: issuesPage([issue(), issue()], 10) });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.equal(http.calls.length, 1);
});

test('total from top-level field (no paging wrapper)', async () => {
  const http = new FakeHttp({
    [ISSUES_PATH]: {
      kind: 'response', status: 200,
      body: new TextEncoder().encode(JSON.stringify({ total: 1, issues: [issue()] })),
      truncated: false,
    },
  });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.equal((JSON.parse(decode(out.raw)) as { total: number }).total, 1);
});

test('bad_key response: failed with bad_api_key diagnostic', async () => {
  const body = new TextEncoder().encode('{"errors":[{"msg":"Unauthorized"}]}');
  const http = new FakeHttp({ [ISSUES_PATH]: { kind: 'response', status: 401, body, truncated: false } });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(codes(out.diagnostics), ['bad_api_key']);
});

test('closed connection: unavailable with sonarqube_unreachable_or_rejected', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: { kind: 'closed' } });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'unavailable');
  assert.deepEqual(codes(out.diagnostics), ['sonarqube_unreachable_or_rejected']);
});

test('timeout: unavailable with sonarqube_unreachable_or_rejected', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: { kind: 'timeout' } });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'unavailable');
  assert.deepEqual(codes(out.diagnostics), ['sonarqube_unreachable_or_rejected']);
});

test('missing issues array in response: failed with tool_execution_failed', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: { kind: 'response', status: 200, body: new TextEncoder().encode('{"paging":{"total":1}}'), truncated: false } });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(codes(out.diagnostics), ['tool_execution_failed']);
});

test('missing total in response: failed with tool_execution_failed', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: { kind: 'response', status: 200, body: new TextEncoder().encode('{"issues":[]}'), truncated: false } });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(codes(out.diagnostics), ['tool_execution_failed']);
});

// The body must physically exceed RAW_JSON_MAX_BYTES so bytesSoFar > limit — there is no injectable limit.
// classify() reads body.byteLength, so this test requires a 50 MiB+ allocation (~1s, unavoidable).
test('byte accumulation: page bytes exceeding raw limit adds coverageLoss, outcome still ok', async () => {
  const padding = Buffer.alloc(RAW_JSON_MAX_BYTES + 100, 0x78).toString(); // 'x' × (50 MiB + 100)
  const http = new FakeHttp({ [ISSUES_PATH]: issuesPage([issue({ message: padding })], 1) });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(codes(out.coverageLoss), ['resource_limit_exceeded']);
  assert.deepEqual(out.diagnostics, []);
  assert.equal(http.calls.length, 1);
});

test('truncated response (too_large): failed with tool_execution_failed', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: { kind: 'response', status: 200, body: new TextEncoder().encode('{}'), truncated: true } });
  const out = await sonarQubeScan(scanCtx(), depsWith(http));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(codes(out.diagnostics), ['tool_execution_failed']);
});

test('the canary token never appears in the request URL', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: issuesPage([], 0) });
  await sonarQubeScan(scanCtx(), depsWith(http));
  for (const call of http.calls) {
    assert.ok(!call.url.includes(CANARY), 'token must not appear in URL');
    assert.ok(!JSON.stringify(call.headers).includes(CANARY), 'token must not appear in plain headers');
  }
});

test('Authorization header is passed as SensitiveString', async () => {
  const { SensitiveString } = await import('../../../../src/contracts/sensitive.js');
  const http = new FakeHttp({ [ISSUES_PATH]: issuesPage([], 0) });
  await sonarQubeScan(scanCtx(), depsWith(http));
  const call = http.calls[0]!;
  assert.ok(call.sensitiveHeaders?.['Authorization'] instanceof SensitiveString);
});

test('base URL trailing slashes are normalized', async () => {
  const http = new FakeHttp({ [ISSUES_PATH]: issuesPage([], 0) });
  await sonarQubeScan(scanCtx({ apiUrl: `${API}///` }), depsWith(http));
  assert.equal(new URL(http.calls[0]!.url).pathname, ISSUES_PATH);
});
