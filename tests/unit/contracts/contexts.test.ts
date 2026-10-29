import assert from 'node:assert/strict';
import { test } from 'node:test';
import type {
  SemgrepProbeContext,
  SemgrepScanContext,
  SonarQubeProbeContext,
  ToolCatalog,
  ZapLiveScanContext,
  ZapProbeContext,
} from '../../../src/contracts/adapter.js';
import { SensitiveString } from '../../../src/contracts/sensitive.js';

const CANARY = 'canary-key-0b6d2e44';
const key = new SensitiveString(CANARY);

test('probe and scan contexts are separate types', () => {
  const semgrepProbe = { producer: 'semgrep' } satisfies SemgrepProbeContext;
  const zapProbe = { producer: 'zap', apiUrl: 'http://127.0.0.1:8090', apiKey: key } satisfies ZapProbeContext;
  const semgrepScan = {
    producer: 'semgrep', rootAbs: '/r', targetRel: 'src', rules: { mode: 'auto' },
    ruleTimeoutSeconds: 5, timeoutSeconds: 600, excludeRelToTarget: null,
  } satisfies SemgrepScanContext;
  const zapScan = {
    producer: 'zap', mode: 'live', scanId: 'id', targetOrigin: 'http://127.0.0.1:8080',
    apiUrl: 'http://127.0.0.1:8090', apiKey: key, sessionMode: 'require_clean',
    spiderTimeoutSeconds: 300, passiveTimeoutSeconds: 120,
  } satisfies ZapLiveScanContext;

  // @ts-expect-error Semgrep probe has no target
  const a: SemgrepProbeContext = { producer: 'semgrep', targetRel: 'src' };
  // @ts-expect-error Semgrep probe has no rules
  const b: SemgrepProbeContext = { producer: 'semgrep', rules: { mode: 'auto' } };
  // @ts-expect-error ZAP probe has no target origin
  const c: ZapProbeContext = { producer: 'zap', apiUrl: 'u', apiKey: key, targetOrigin: 'http://x' };
  // @ts-expect-error ZAP probe has no scan ID
  const d: ZapProbeContext = { producer: 'zap', apiUrl: 'u', apiKey: key, scanId: 'x' };
  // @ts-expect-error ZAP probe requires the key
  const e: ZapProbeContext = { producer: 'zap', apiUrl: 'u' };
  // @ts-expect-error live scan API key is not nullable
  const f: ZapLiveScanContext = { ...zapScan, apiKey: null };
  // @ts-expect-error live scan API URL is not nullable
  const g: ZapLiveScanContext = { ...zapScan, apiUrl: null };
  // @ts-expect-error live scan is not offline
  const h: ZapLiveScanContext = { ...zapScan, mode: 'offline' };
  void [a, b, c, d, e, f, g, h];

  assert.deepEqual(Object.keys(zapProbe).sort(), ['apiKey', 'apiUrl', 'producer']);
  for (const ctx of [semgrepProbe, zapProbe, semgrepScan, zapScan]) {
    assert.equal(JSON.stringify(ctx).includes(CANARY), false);
  }
});

test('catalog wires probe and scan contexts per tool', () => {
  const sonarqubeCtx: SonarQubeProbeContext = { producer: 'sonarqube', apiUrl: 'http://localhost:9000', apiKey: key, projectKey: 'my-project' };
  const check = (t: ToolCatalog) => {
    void t.semgrep.probe({ producer: 'semgrep' }, undefined as never);
    void t.zap.probe({ producer: 'zap', apiUrl: 'u', apiKey: key }, undefined as never);
    void t.sonarqube.probe(sonarqubeCtx, undefined as never);
  };
  assert.equal(typeof check, 'function');
});
