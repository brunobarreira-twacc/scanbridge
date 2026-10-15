import assert from 'node:assert/strict';
import { existsSync, readFileSync, truncateSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { RAW_JSON_MAX_BYTES } from '../../../src/contracts/limits.js';
import {
  CANARY_API_KEY,
  ORIGIN,
  allArtifactText,
  codes,
  configYaml,
  envelope,
  filesIn,
  liveEnv,
  makeRepo,
  readJson,
  runCli,
  scanDirectory,
  startZap,
  zapAlert,
  type CliRun,
  type Repo,
  type ZapBehavior,
} from './harness.js';

const LIVE = ['scan', '--adapter', 'zap', '--target-url', ORIGIN, '--output', 'out'];

function assertContract(run: CliRun, repo: Repo): string | null {
  assert.ok(run.stdout.endsWith('\n'));
  JSON.parse(run.stdout);
  const dir = scanDirectory(repo);
  if (dir !== null && existsSync(join(dir, 'scan-result.json'))) {
    assert.equal(readFileSync(join(dir, 'scan-result.json'), 'utf8'), run.stdout);
  }
  return dir;
}

async function withZap<T>(behavior: ZapBehavior, body: (zap: Awaited<ReturnType<typeof startZap>>) => Promise<T>): Promise<T> {
  const zap = await startZap(behavior);
  try {
    return await body(zap);
  } finally {
    await zap.close();
  }
}

describe('zap live scan', () => {
  it('happy path: complete, authoritative, key only in the header', async () => {
    const alerts = [zapAlert(), zapAlert({ pluginId: '10038', alertRef: '10038-1', name: 'CSP', alert: 'CSP', url: `${ORIGIN}/`, method: 'GET', risk: 'Low' })];
    await withZap({ alerts }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, [...LIVE, '--target-revision', 'rev-1'], liveEnv(zap));
      assert.equal(run.status, 0, run.stderr);
      const env = envelope(run);
      assert.equal(env.status, 'complete');
      assert.equal(env.authoritative, true);
      assert.equal(env.findings_count, 2);
      const dir = assertContract(run, repo) as string;
      assert.deepEqual(filesIn(dir), ['normalized.json', 'raw/zap.json', 'scan-result.json']);
      const normalized = readJson(join(dir, 'normalized.json'));
      assert.deepEqual(normalized.target, { kind: 'http_origin', origin: ORIGIN, asserted_revision: 'rev-1' });
      assert.equal(normalized.producer_version, '2.15.0');
      assert.equal(normalized.rules_digest, null);
      assert.ok(zap.requests.length > 5);
      for (const request of zap.requests) {
        assert.equal(request.key, CANARY_API_KEY);
        assert.ok(!request.query.toString().includes(CANARY_API_KEY));
      }
      assert.ok(!allArtifactText(dir).includes(CANARY_API_KEY));
      assert.ok(!run.stdout.includes(CANARY_API_KEY) && !run.stderr.includes(CANARY_API_KEY));
      // The raw artifact is the assembled `{"alerts":[...]}` document.
      assert.equal(readJson(join(dir, 'raw', 'zap.json')).alerts.length, 2);
    });
  });

  it('dirty session: exit 3, no raw, no normalized, scan-result.json equals stdout', async () => {
    await withZap({ existingAlerts: 3 }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 3);
      const env = envelope(run);
      assert.equal(env.status, 'failed');
      assert.ok(codes(env).includes('zap_session_not_clean'));
      const dir = assertContract(run, repo) as string;
      assert.deepEqual(filesIn(dir), ['scan-result.json']);
      assert.equal(env.artifacts.raw, null);
      assert.equal(env.artifacts.normalized, null);
    });
  });

  it('reset mode starts with newSession and then scans', async () => {
    await withZap({ existingAlerts: 3, alerts: [zapAlert()] }, async (zap) => {
      const repo = makeRepo({}, configYaml({ sessionMode: 'reset' }));
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 0, run.stderr);
      const paths = zap.requests.map((r) => r.path);
      assert.ok(paths.indexOf('/JSON/core/action/newSession/') < paths.indexOf('/JSON/context/action/newContext/'));
    });
  });

  it('bad API key: exit 2 with bad_api_key, scan-result.json only', async () => {
    await withZap({}, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap, 'wrong-canary-key-0000'));
      assert.equal(run.status, 2);
      const env = envelope(run);
      assert.ok(codes(env).includes('bad_api_key'));
      const dir = assertContract(run, repo) as string;
      assert.deepEqual(filesIn(dir), ['scan-result.json']);
      assert.ok(!run.stdout.includes('wrong-canary-key-0000') && !run.stderr.includes('wrong-canary-key-0000'));
    });
  });

  it('closed connection: exit 2 with zap_unreachable_or_rejected', async () => {
    await withZap({ closed: true }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 2);
      assert.ok(codes(envelope(run)).includes('zap_unreachable_or_rejected'));
      assertContract(run, repo);
    });
  });

  it('spider deadline: partial with tool_timeout, exit 4', async () => {
    await withZap({ spiderStatus: '50', alerts: [zapAlert()] }, async (zap) => {
      const repo = makeRepo({}, configYaml({ spiderTimeout: 1 }));
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 4);
      const env = envelope(run);
      assert.equal(env.status, 'partial');
      assert.ok(codes(env).includes('tool_timeout'));
      assert.deepEqual(env.non_authoritative_reasons, ['partial_scan']);
      assert.ok(zap.requests.some((r) => r.path === '/JSON/spider/action/stop/'));
      assert.deepEqual(filesIn(assertContract(run, repo) as string), ['normalized.json', 'raw/zap.json', 'scan-result.json']);
    });
  });

  it('zero discovered URLs: partial with no_urls_discovered', async () => {
    await withZap({ spiderResults: [] }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 4);
      assert.ok(codes(envelope(run)).includes('no_urls_discovered'));
    });
  });

  it('alert count changing while paging: partial', async () => {
    await withZap({ alerts: [zapAlert()], countAfterPaging: 9 }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 4);
      assert.ok(codes(envelope(run)).includes('partial_coverage'));
    });
  });

  it('out-of-scope alerts are excluded and counted, the scan stays complete', async () => {
    await withZap({ alerts: [zapAlert(), zapAlert({ pluginId: '1', url: 'http://127.0.0.2:9/x' })] }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 0, run.stderr);
      const env = envelope(run);
      assert.equal(env.status, 'complete');
      assert.equal(env.findings_count, 1);
      assert.ok(codes(env).includes('out_of_scope_target'));
    });
  });

  it('pages: more than one alert page is merged in page order', async () => {
    const alerts = Array.from({ length: 501 }, (_, i) => zapAlert({ pluginId: String(1000 + i), alertRef: `${1000 + i}-1`, url: `${ORIGIN}/p${i}` }));
    await withZap({ alerts }, async (zap) => {
      const repo = makeRepo();
      const run = await runCli(repo, LIVE, liveEnv(zap));
      assert.equal(run.status, 0, run.stderr);
      assert.equal(envelope(run).findings_count, 501);
      const raw = readJson(join(scanDirectory(repo) as string, 'raw', 'zap.json'));
      assert.equal(raw.alerts.length, 501);
      assert.equal(raw.alerts[500].pluginId, '1500');
    });
  });
});

describe('zap input rules', () => {
  it('missing API key variable: exit 2, tool_unavailable, artifacts null, nothing created', async () => {
    const repo = makeRepo();
    const run = await runCli(repo, LIVE, { SCANBRIDGE_ZAP_API_URL: 'http://127.0.0.1:9' });
    assert.equal(run.status, 2);
    const env = envelope(run);
    assert.equal(env.status, 'failed');
    assert.deepEqual(env.artifacts, { directory: null, raw: null, normalized: null });
    assert.deepEqual(codes(env), ['tool_unavailable']);
    assert.equal(existsSync(join(repo.root, 'out')), false);
  });

  it('non-loopback API URL from the environment: exit 2', async () => {
    const repo = makeRepo();
    const run = await runCli(repo, LIVE, { SCANBRIDGE_ZAP_API_URL: 'http://192.0.2.1:8080', SCANBRIDGE_ZAP_API_KEY: CANARY_API_KEY });
    assert.equal(run.status, 2);
    assert.ok(!run.stdout.includes('192.0.2.1'));
  });

  it('target URL flag outside the allowlist: usage error, exit 1', async () => {
    const repo = makeRepo();
    const run = await runCli(repo, ['scan', '--adapter', 'zap', '--target-url', 'http://127.0.0.1:9999', '--output', 'out'], {});
    assert.equal(run.status, 1);
    assert.equal(JSON.parse(run.stdout).error.code, 'usage_error');
  });

  it('target URL from the environment variable; flag plus variable adds target_url_overridden', async () => {
    await withZap({ alerts: [zapAlert()] }, async (zap) => {
      const repo = makeRepo();
      const fromEnv = await runCli(repo, ['scan', '--adapter', 'zap', '--output', 'out'], { ...liveEnv(zap), SCANBRIDGE_ZAP_TARGET_URL: ORIGIN });
      assert.equal(fromEnv.status, 0, fromEnv.stderr);
      assert.ok(!codes(envelope(fromEnv)).includes('target_url_overridden'));
    });
    // A fresh fake: the first scan left alerts in the previous session, which require_clean rightly refuses.
    await withZap({ alerts: [zapAlert()] }, async (zap) => {
      const repo = makeRepo();
      const both = await runCli(repo, LIVE, { ...liveEnv(zap), SCANBRIDGE_ZAP_TARGET_URL: ORIGIN });
      assert.equal(both.status, 0, both.stderr);
      assert.ok(codes(envelope(both)).includes('target_url_overridden'));
      assert.match(both.stderr, /overrides/);
    });
  });

  it('no target URL anywhere: exit 2', async () => {
    const repo = makeRepo();
    const run = await runCli(repo, ['scan', '--adapter', 'zap', '--output', 'out'], {
      SCANBRIDGE_ZAP_API_URL: 'http://127.0.0.1:9',
      SCANBRIDGE_ZAP_API_KEY: CANARY_API_KEY,
    });
    assert.equal(run.status, 2);
  });
});

function offlineRepo(report: string | Buffer = JSON.stringify({ alerts: [zapAlert()] })): Repo {
  const repo = makeRepo();
  writeFileSync(join(repo.root, 'alerts.json'), report);
  return repo;
}

const OFFLINE = ['scan', '--adapter', 'zap', '--from-report', 'alerts.json', '--output', 'out'];

describe('zap offline import', () => {
  it('flag target, no API variables at all: unverified, exit 0, offline_report', async () => {
    const repo = offlineRepo();
    const run = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN, '--target-revision', 'r1', '--producer-version', '2.15.0'], {});
    assert.equal(run.status, 0, run.stderr);
    const env = envelope(run);
    assert.equal(env.status, 'unverified');
    assert.equal(env.authoritative, false);
    assert.deepEqual(env.non_authoritative_reasons, ['offline_report']);
    assert.equal(env.findings_count, 1);
    const dir = assertContract(run, repo) as string;
    const normalized = readJson(join(dir, 'normalized.json'));
    assert.equal(normalized.producer_version, '2.15.0');
    assert.deepEqual(normalized.target, { kind: 'http_origin', origin: ORIGIN, asserted_revision: 'r1' });
    assert.equal(normalized.completeness, 'unverified');
  });

  it('producer_version is null without --producer-version', async () => {
    const repo = offlineRepo();
    const run = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN]);
    assert.equal(run.status, 0, run.stderr);
    assert.equal(readJson(join(scanDirectory(repo) as string, 'normalized.json')).producer_version, null);
  });

  it('target URL from the environment, and flag wins with target_url_overridden', async () => {
    const repo = offlineRepo();
    const fromEnv = await runCli(repo, OFFLINE, { SCANBRIDGE_ZAP_TARGET_URL: ORIGIN });
    assert.equal(fromEnv.status, 0, fromEnv.stderr);
    assert.ok(!codes(envelope(fromEnv)).includes('target_url_overridden'));
    const both = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN], { SCANBRIDGE_ZAP_TARGET_URL: ORIGIN });
    assert.equal(both.status, 0, both.stderr);
    assert.ok(codes(envelope(both)).includes('target_url_overridden'));
  });

  it('neither flag nor variable: exit 2', async () => {
    const repo = offlineRepo();
    const run = await runCli(repo, OFFLINE);
    assert.equal(run.status, 2);
    assert.deepEqual(envelope(run).artifacts, { directory: null, raw: null, normalized: null });
  });

  it('alerts outside the target origin are excluded', async () => {
    const repo = offlineRepo(JSON.stringify({ alerts: [zapAlert(), zapAlert({ pluginId: '2', url: 'http://127.0.0.2:1/x' })] }));
    const run = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN]);
    assert.equal(run.status, 0, run.stderr);
    assert.ok(codes(envelope(run)).includes('out_of_scope_target'));
  });

  for (const [name, content] of [
    ['malformed JSON', '{"alerts": ['],
    ['Traditional report', JSON.stringify({ '@version': '2', site: [] })],
    ['wrong shape', JSON.stringify({ alerts: {} })],
  ] as const) {
    it(`${name}: exit 3, scan-result.json only`, async () => {
      const repo = offlineRepo(content);
      const run = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN]);
      assert.equal(run.status, 3);
      const env = envelope(run);
      assert.equal(env.status, 'failed');
      assert.ok(codes(env).includes('malformed_report'));
      assert.deepEqual(filesIn(assertContract(run, repo) as string), ['scan-result.json']);
    });
  }

  it('a missing report file: exit 3, scan-result.json only', async () => {
    const repo = makeRepo();
    const run = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN]);
    assert.equal(run.status, 3);
    assert.deepEqual(filesIn(assertContract(run, repo) as string), ['scan-result.json']);
  });

  it('raw size boundary: one below and exactly at the limit pass, one above fails', async () => {
    const empty = '{"alerts":[]}';
    for (const [size, status] of [
      [RAW_JSON_MAX_BYTES - 1, 0],
      [RAW_JSON_MAX_BYTES, 0],
      [RAW_JSON_MAX_BYTES + 1, 3],
    ] as const) {
      const repo = offlineRepo(empty);
      const path = join(repo.root, 'alerts.json');
      writeFileSync(path, empty);
      truncateSync(path, size);
      // Whitespace padding: after the document, the file is NUL-free spaces.
      const body = Buffer.alloc(size, 0x20);
      body.write(empty, 0);
      writeFileSync(path, body);
      const run = await runCli(repo, [...OFFLINE, '--target-url', ORIGIN]);
      assert.equal(run.status, status, `size ${size}: ${run.stdout.slice(0, 300)}`);
      const env = envelope(run);
      if (status === 3) {
        assert.ok(codes(env).includes('resource_limit_exceeded'));
        assert.deepEqual(filesIn(assertContract(run, repo) as string), ['scan-result.json']);
      } else {
        assert.equal(env.status, 'unverified');
      }
    }
  });
});
