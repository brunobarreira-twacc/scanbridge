import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { SensitiveString } from '../../../src/contracts/sensitive.js';
import { main } from '../../../src/cli/main.js';
import { BASE_ENV, CANARY_KEY, scratchRepo } from '../config/helpers.js';
import { cliDeps, envOf, fakePorts, unavailableProbe } from './fakes.js';

const config = ({ semgrep = true, zap = true }: { semgrep?: boolean; zap?: boolean } = {}) => `version: 1
tools:
  semgrep:
    enabled: ${semgrep}
    config:
      rules: [rules/security.yaml]
  zap:
    enabled: ${zap}
    config:
      api_url_env: SCANBRIDGE_ZAP_API_URL
      api_key_env: SCANBRIDGE_ZAP_API_KEY
      target_url_env: SCANBRIDGE_ZAP_TARGET_URL
      allowed_target_origins: ["http://127.0.0.1:8080"]
`;

/** Scratch directories are removed by the cleanup hook in `scratchRepo`. */
function repo(yaml = config()) {
  return scratchRepo(yaml);
}

/** Runs `doctor` in-process; `configPath` is absolute, so the cwd only matters for relative paths. */
async function doctor(
  options: Parameters<typeof fakePorts>[0],
  env: Record<string, string | undefined>,
  yaml?: string,
) {
  const { root, configPath } = repo(yaml);
  const ports = fakePorts(options);
  const run = cliDeps({ cwd: root, env: envOf(env), ports });
  const exitCode = await main(['doctor', '--config', configPath], run.deps);
  return { exitCode, ports, stdout: run.stdout.text, stderr: run.stderr.text, json: JSON.parse(run.stdout.text) };
}

describe('doctor: zap readiness', () => {
  it('passes the SensitiveString through unchanged and never prints the key', async () => {
    const reveal = mock.method(SensitiveString.prototype, 'reveal');
    try {
      const result = await doctor({}, { ...BASE_ENV });
      assert.equal(result.exitCode, 0);

      const [context] = result.ports.calls.zap;
      assert.equal(context?.producer, 'zap');
      assert.ok(context?.apiKey instanceof SensitiveString);
      assert.equal(reveal.mock.callCount(), 0, 'doctor must never call reveal()');

      assert.equal(result.stdout.includes(CANARY_KEY), false);
      assert.equal(result.stderr.includes(CANARY_KEY), false);
      assert.equal(JSON.stringify(result.json).includes(CANARY_KEY), false);

      const zap = result.json.tools.find((tool: { name: string }) => tool.name === 'zap');
      assert.equal(zap.api_key, 'present');
      assert.equal(zap.api_key_verified, false);
      assert.equal(zap.status, 'ready');
      assert.equal(zap.version, '2.10.0');
    } finally {
      reveal.mock.restore();
    }
  });

  it('is ready without SCANBRIDGE_ZAP_TARGET_URL set', async () => {
    const { SCANBRIDGE_ZAP_TARGET_URL: _unused, ...withoutTarget } = BASE_ENV;
    const result = await doctor({}, withoutTarget);
    assert.equal(result.exitCode, 0);
    assert.equal(result.json.ok, true);
  });

  it('never reads the target URL variable', async () => {
    const { root, configPath } = repo();
    const strictEnv = {
      get: (name: string) => {
        if (name === 'SCANBRIDGE_ZAP_TARGET_URL') throw new Error('target_url_env must not be read by doctor');
        return BASE_ENV[name];
      },
    };
    const run = cliDeps({ cwd: root, env: strictEnv, ports: fakePorts({}) });
    const exitCode = await main(['doctor', '--config', configPath], run.deps);
    assert.equal(exitCode, 0);
  });

  it('reports a missing key as missing, skips the probe and exits 2', async () => {
    const { SCANBRIDGE_ZAP_API_KEY: _unused, ...withoutKey } = BASE_ENV;
    const result = await doctor({}, withoutKey);
    assert.equal(result.exitCode, 2);
    assert.equal(result.ports.calls.zap.length, 0, 'no ZAP probe without a key');

    const zap = result.json.tools.find((tool: { name: string }) => tool.name === 'zap');
    assert.equal(zap.status, 'unavailable');
    assert.equal(zap.api_key, 'missing');
    assert.equal(zap.api_key_verified, false);
    assert.deepEqual(zap.problems, [
      { code: 'tool_unavailable', message: 'SCANBRIDGE_ZAP_API_KEY is not set' },
    ]);
  });

  it('skips the probe for a non-loopback API URL and exits 2', async () => {
    const result = await doctor({}, { ...BASE_ENV, SCANBRIDGE_ZAP_API_URL: 'http://example.com:8080' });
    assert.equal(result.exitCode, 2);
    assert.equal(result.ports.calls.zap.length, 0);
    assert.equal(result.json.tools[1].api_key, 'present');
  });

  it('passes the probe result through when ZAP is unavailable', async () => {
    const result = await doctor({ zap: async () => unavailableProbe('zap') }, { ...BASE_ENV });
    assert.equal(result.exitCode, 2);
    assert.equal(result.json.tools[1].status, 'unavailable');
    assert.equal(result.json.tools[1].problems[0].code, 'tool_unavailable');
  });
});

describe('doctor: semgrep and disabled tools', () => {
  it('calls the Semgrep probe with the producer only, no target', async () => {
    const result = await doctor({}, { ...BASE_ENV });
    assert.deepEqual(result.ports.calls.semgrep, [{ producer: 'semgrep' }]);
    assert.equal('target' in (result.ports.calls.semgrep[0] ?? {}), false);
  });

  it('marks disabled tools as skipped without probing them', async () => {
    const result = await doctor({}, { ...BASE_ENV }, config({ semgrep: false, zap: false }));
    assert.equal(result.exitCode, 0);
    assert.deepEqual(
      result.json.tools.map((tool: { status: string }) => tool.status),
      ['skipped', 'skipped'],
    );
    assert.equal(result.ports.calls.semgrep.length + result.ports.calls.zap.length, 0);
  });

  it('exits 2 when Semgrep is unavailable', async () => {
    const result = await doctor({ semgrep: async () => unavailableProbe('semgrep') }, { ...BASE_ENV });
    assert.equal(result.exitCode, 2);
    assert.equal(result.json.ok, false);
  });

  it('treats a throwing probe as unavailable without copying its message', async () => {
    const result = await doctor(
      {
        semgrep: async () => {
          throw new Error(`boom ${CANARY_KEY}`);
        },
      },
      { ...BASE_ENV },
    );
    assert.equal(result.exitCode, 2);
    assert.equal(result.json.tools[0].status, 'unavailable');
    assert.equal(result.stdout.includes(CANARY_KEY), false);
  });

  it('reports unavailable tools when no adapters are wired into the build', async () => {
    const { root, configPath } = repo();
    const run = cliDeps({ cwd: root, env: envOf({ ...BASE_ENV }) });
    const exitCode = await main(['doctor', '--config', configPath], run.deps);
    assert.equal(exitCode, 2);
    assert.equal(JSON.parse(run.stdout.text).ok, false);
  });
});
