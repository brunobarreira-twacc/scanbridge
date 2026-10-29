import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import { codes, configYaml, envelope, filesIn, makeRepo, readJson, runCli, scanDirectory } from './harness.js';

type SqBehavior = {
  version?: string;
  apiKey?: string;
  issues?: unknown[];
  total?: number;
  projectKey?: string;
  versionStatus?: number;
  issuesStatus?: number;
  closed?: boolean;
  malformedIssuesJson?: boolean;
};

type SqFake = { apiUrl: string; close(): Promise<void> };

async function startSq(b: SqBehavior = {}): Promise<SqFake> {
  const key = b.apiKey ?? 'canary-sq-token-contract';
  const issues = b.issues ?? [];
  const total = b.total ?? issues.length;
  const projectKey = b.projectKey ?? 'contract-test-project';

  const send = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (b.closed) { req.socket.destroy(); return; }

    const auth = req.headers['authorization'];
    if (url.pathname === '/api/server/version') {
      if (b.versionStatus !== undefined && b.versionStatus !== 200) {
        return send(res, b.versionStatus, { errors: [{ msg: 'unauthorized' }] });
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(b.version ?? '10.6.0');
      return;
    }
    if (url.pathname === '/api/issues/search') {
      if (!auth || auth !== `Bearer ${key}`) {
        return send(res, 401, { errors: [{ msg: 'Unauthorized' }] });
      }
      if (b.issuesStatus !== undefined && b.issuesStatus !== 200) {
        return send(res, b.issuesStatus, { errors: [{ msg: 'error' }] });
      }
      if (b.malformedIssuesJson) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('not-valid-json');
        return;
      }
      return send(res, 200, { paging: { total, pageIndex: 1, pageSize: 500 }, issues });
    }
    return send(res, 404, { errors: [{ msg: 'not found' }] });
  };
  const server: Server = createServer(handler);
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const { port } = server.address() as AddressInfo;
  return {
    apiUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((done) => { server.closeAllConnections(); server.close(() => done()); }),
  };
}

const SQ_KEY = 'canary-sq-token-contract';
const SQ_PROJECT = 'contract-test-project';
const SCAN_ARGS = ['scan', '--adapter', 'sonarqube', '--output', 'out'];

function sqEnv(apiUrl: string, key = SQ_KEY, project = SQ_PROJECT): Record<string, string> {
  return { SONARQUBE_URL: apiUrl, SONARQUBE_TOKEN: key, SONARQUBE_PROJECT: project };
}

function sqConfig(enabled = true): string {
  return configYaml({ semgrepEnabled: false, zapEnabled: false, sonarqubeEnabled: enabled });
}

describe('sonarqube scan', () => {
  it('complete scan with no findings: exit 0, complete, zero findings', async () => {
    const sq = await startSq({ apiKey: SQ_KEY, issues: [], total: 0 });
    try {
      const repo = makeRepo({}, sqConfig());
      const run = await runCli(repo, SCAN_ARGS, sqEnv(sq.apiUrl));
      assert.equal(run.status, 0, run.stderr);
      const env = envelope(run);
      assert.equal(env.status, 'complete');
      assert.equal(env.authoritative, true);
      assert.equal(env.findings_count, 0);
      const dir = scanDirectory(repo) as string;
      assert.ok(dir !== null, 'scan directory created');
      assert.deepEqual(filesIn(dir), ['normalized.json', 'raw/sonarqube.json', 'scan-result.json']);
      const normalized = readJson(`${dir}/normalized.json`);
      assert.equal(normalized.producer_version, '10.6.0');
      assert.equal(normalized.rules_digest, null);
    } finally {
      await sq.close();
    }
  });

  it('scan with findings: exit 0, expected count, raw artifact written', async () => {
    const issues = [
      { key: 'K1', rule: 'java:S2259', component: 'contract-test-project:src/App.java', type: 'BUG', message: 'NPE.', impacts: [{ softwareQuality: 'RELIABILITY', severity: 'BLOCKER' }] },
      { key: 'K2', rule: 'javasecurity:S3649', component: 'contract-test-project:src/DB.java', type: 'VULNERABILITY', message: 'SQL injection.', impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }] },
    ];
    const sq = await startSq({ apiKey: SQ_KEY, issues, total: 2 });
    try {
      const repo = makeRepo({}, sqConfig());
      const run = await runCli(repo, SCAN_ARGS, sqEnv(sq.apiUrl));
      assert.equal(run.status, 0, run.stderr);
      const env = envelope(run);
      assert.equal(env.status, 'complete');
      assert.equal(env.findings_count, 2);
      const dir = scanDirectory(repo) as string;
      const raw = readJson(`${dir}/raw/sonarqube.json`);
      assert.equal(raw.issues.length, 2);
      assert.equal(raw.projectKey, SQ_PROJECT);
    } finally {
      await sq.close();
    }
  });

  it('API unavailable (closed): exit 2, failed status, sonarqube_unreachable_or_rejected', async () => {
    const sq = await startSq({ closed: true });
    try {
      const repo = makeRepo({}, sqConfig());
      const run = await runCli(repo, SCAN_ARGS, sqEnv(sq.apiUrl));
      assert.equal(run.status, 2, run.stdout);
      const env = envelope(run);
      assert.equal(env.status, 'failed');
      assert.ok(codes(env).includes('sonarqube_unreachable_or_rejected'));
    } finally {
      await sq.close();
    }
  });

  it('bad API key: exit 2, bad_api_key diagnostic', async () => {
    const sq = await startSq({ apiKey: 'different-key', versionStatus: 401 });
    try {
      const repo = makeRepo({}, sqConfig());
      const run = await runCli(repo, SCAN_ARGS, sqEnv(sq.apiUrl));
      assert.equal(run.status, 2, run.stdout);
      const env = envelope(run);
      assert.ok(codes(env).includes('bad_api_key'));
    } finally {
      await sq.close();
    }
  });

  it('adapter disabled in config: usage_error, exit 1', async () => {
    const repo = makeRepo({}, sqConfig(false));
    const run = await runCli(repo, SCAN_ARGS, { SONARQUBE_URL: 'http://127.0.0.1:9999', SONARQUBE_TOKEN: SQ_KEY, SONARQUBE_PROJECT: SQ_PROJECT });
    assert.equal(run.status, 1);
    const env = envelope(run);
    assert.equal(env.status, 'error');
    assert.equal((env as unknown as { error: { code: string } }).error.code, 'usage_error');
  });

  it('missing SONARQUBE_URL: exit 2, tool_unavailable', async () => {
    const repo = makeRepo({}, sqConfig());
    const run = await runCli(repo, SCAN_ARGS, { SONARQUBE_TOKEN: SQ_KEY, SONARQUBE_PROJECT: SQ_PROJECT });
    assert.equal(run.status, 2, run.stdout);
    const env = envelope(run);
    assert.ok(codes(env).includes('tool_unavailable'));
  });

  it('invalid configuration: exit 1, invalid_configuration', async () => {
    const repo = makeRepo({}, 'version: 2\n');
    const run = await runCli(repo, SCAN_ARGS, { SONARQUBE_URL: 'http://127.0.0.1:9999', SONARQUBE_TOKEN: SQ_KEY, SONARQUBE_PROJECT: SQ_PROJECT });
    assert.equal(run.status, 1);
    const result = JSON.parse(run.stdout) as { error?: { code: string } };
    assert.equal(result.error?.code, 'invalid_configuration');
  });

  it('malformed JSON response: exit 3, failed status, tool_execution_failed', async () => {
    const sq = await startSq({ apiKey: SQ_KEY, malformedIssuesJson: true });
    try {
      const repo = makeRepo({}, sqConfig());
      const run = await runCli(repo, SCAN_ARGS, sqEnv(sq.apiUrl));
      assert.equal(run.status, 3, run.stdout);
      const env = envelope(run);
      assert.equal(env.status, 'failed');
      assert.ok(codes(env).includes('tool_execution_failed'));
    } finally {
      await sq.close();
    }
  });

  it('stdout is exactly one newline-terminated JSON document', async () => {
    const sq = await startSq({ apiKey: SQ_KEY });
    try {
      const repo = makeRepo({}, sqConfig());
      const run = await runCli(repo, SCAN_ARGS, sqEnv(sq.apiUrl));
      assert.ok(run.stdout.endsWith('\n'), 'stdout ends with newline');
      JSON.parse(run.stdout);
    } finally {
      await sq.close();
    }
  });
});
