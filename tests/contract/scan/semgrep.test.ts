import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import {
  FIXTURES,
  SOURCE_LINES,
  allArtifactText,
  codes,
  configYaml,
  envelope,
  filesIn,
  installFakeSemgrep,
  makeRepo,
  readJson,
  runCli,
  scanDirectory,
  semgrepArgv,
  semgrepOutput,
  semgrepResult,
  tempDir,
  type CliRun,
  type Repo,
  type SemgrepSpec,
} from './harness.js';

const SCAN = ['scan', '--adapter', 'semgrep', '--target', '.', '--output', 'out'];

function repoWith(spec: SemgrepSpec, files: Record<string, string> = { 'src/app.js': SOURCE_LINES }, config?: string): Repo {
  const repo = makeRepo(files, config);
  installFakeSemgrep(repo, spec);
  return repo;
}

/** stdout is exactly the content of scan-result.json whenever a scan directory exists. */
function assertContract(run: CliRun, repo: Repo, output = 'out'): string | null {
  assert.ok(run.stdout.endsWith('\n'));
  assert.equal(run.stdout.split('\n').filter(Boolean).length > 0, true);
  JSON.parse(run.stdout);
  const dir = scanDirectory(repo, output);
  if (dir !== null && existsSync(join(dir, 'scan-result.json'))) {
    assert.equal(readFileSync(join(dir, 'scan-result.json'), 'utf8'), run.stdout);
  }
  return dir;
}

describe('semgrep scan: outcomes', () => {
  it('complete with no findings: exit 0, authoritative, all artifacts', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 0, run.stderr);
    const env = envelope(run);
    assert.equal(env.status, 'complete');
    assert.equal(env.authoritative, true);
    assert.equal(env.findings_count, 0);
    assert.deepEqual(env.artifacts.raw, ['raw/semgrep.json']);
    assert.equal(env.artifacts.normalized, 'normalized.json');
    const dir = assertContract(run, repo) as string;
    assert.deepEqual(filesIn(dir), ['normalized.json', 'raw/semgrep.json', 'scan-result.json']);
    const normalized = readJson(join(dir, 'normalized.json'));
    assert.equal(normalized.producer, 'semgrep');
    assert.equal(normalized.producer_version, '1.2.3');
    assert.deepEqual(normalized.findings, []);
    assert.match(normalized.rules_digest, /^[0-9a-f]{64}$/);
    assert.equal(run.stderr, '');
  });

  it('findings: exact fingerprint, metavars removed from raw, hashes of original and persisted bytes', async () => {
    const stdout = semgrepOutput({ results: [semgrepResult()] });
    const repo = repoWith({ stdout });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 0, run.stderr);
    const env = envelope(run);
    assert.equal(env.findings_count, 1);
    const dir = assertContract(run, repo) as string;
    const rawText = readFileSync(join(dir, 'raw', 'semgrep.json'), 'utf8');
    assert.ok(!rawText.includes('abstract_content'), 'metavars removed');
    assert.ok(rawText.endsWith('}\n') && !rawText.endsWith('\n\n'));
    const normalized = readJson(join(dir, 'normalized.json'));
    const { createHash } = await import('node:crypto');
    assert.equal(normalized.raw_sha256_before_redaction, createHash('sha256').update(stdout).digest('hex'));
    assert.equal(normalized.raw_sha256_after_redaction, createHash('sha256').update(rawText).digest('hex'));
    assert.equal(normalized.redaction_summary['removed-path'], 1);
    assert.equal(normalized.findings[0].fingerprint_quality, 'exact');
    assert.equal(normalized.findings[0].occurrences[0].source_location.path, 'src/app.js');
    assert.equal(normalized.target.kind, 'directory');
  });

  it('partial scan: exit 4 and all evidence written', async () => {
    const errors = [{ type: 'Timeout', level: 'warn', message: 'timed out' }];
    const repo = repoWith({ stdout: semgrepOutput({ results: [semgrepResult()], errors }) });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 4);
    const env = envelope(run);
    assert.equal(env.status, 'partial');
    assert.deepEqual(env.non_authoritative_reasons, ['partial_scan']);
    assert.ok(codes(env).includes('partial_coverage'));
    const dir = assertContract(run, repo) as string;
    assert.deepEqual(filesIn(dir), ['normalized.json', 'raw/semgrep.json', 'scan-result.json']);
  });

  const fixtureDirs = readdirSync(join(FIXTURES, 'semgrep')).filter((n) => n !== 'findings');
  for (const name of fixtureDirs) {
    it(`fixture ${name} maps to the documented status and exit code`, async () => {
      const base = join(FIXTURES, 'semgrep', name);
      const raw = readFileSync(join(base, 'raw.json'), 'utf8');
      const expected = readJson(join(base, 'expected.json')).completeness as 'complete' | 'partial' | 'failed';
      const parsed = JSON.parse(raw) as { results: { path?: string }[] };
      const files: Record<string, string> = { 'src/app.js': SOURCE_LINES };
      for (const r of parsed.results) if (typeof r.path === 'string') files[r.path] = SOURCE_LINES;
      const repo = repoWith({ stdout: raw }, files);
      const run = await runCli(repo, SCAN);
      const env = envelope(run);
      assert.equal(env.status, expected);
      assert.equal(run.status, { complete: 0, partial: 4, failed: 3 }[expected]);
      const dir = assertContract(run, repo) as string;
      assert.equal(existsSync(join(dir, 'normalized.json')), expected !== 'failed');
      assert.equal(existsSync(join(dir, 'raw', 'semgrep.json')), true, 'accepted raw evidence is kept');
    });
  }

  it('non-zero exit: failed, no raw, no normalized, redacted stderr detail', async () => {
    const repo = repoWith({ exitCode: 2, stderr: 'boom password=hunter2-canary-value\n' });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 3);
    const env = envelope(run);
    assert.equal(env.status, 'failed');
    assert.ok(codes(env).includes('tool_execution_failed'));
    const dir = assertContract(run, repo) as string;
    assert.deepEqual(filesIn(dir), ['scan-result.json']);
    assert.equal(env.artifacts.raw, null);
    assert.equal(env.artifacts.normalized, null);
    assert.ok(!run.stdout.includes('hunter2-canary-value'));
    assert.ok(!run.stderr.includes('hunter2-canary-value'));
  });

  it('invalid JSON from the producer: failed, no raw artifact', async () => {
    const repo = repoWith({ stdout: 'not json' });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 3);
    assert.ok(codes(envelope(run)).includes('malformed_report'));
    assert.deepEqual(filesIn(assertContract(run, repo) as string), ['scan-result.json']);
  });

  it('unavailable semgrep (probe fails): exit 2, scan-result.json only', async () => {
    const repo = repoWith({ versionExit: 1 });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 2);
    assert.ok(codes(envelope(run)).includes('tool_unavailable'));
    assert.deepEqual(filesIn(assertContract(run, repo) as string), ['scan-result.json']);
    assert.deepEqual(semgrepArgv(repo), [['--version']]);
  });

  it('semgrep missing from PATH: exit 2', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const empty = tempDir('scanbridge-empty-');
    const run = await runCli(repo, SCAN, { PATH: empty });
    assert.equal(run.status, 2);
    assert.equal(envelope(run).status, 'failed');
  });

  it('no files scanned: partial with no_files_scanned', async () => {
    const repo = repoWith({ stdout: semgrepOutput({ scanned: [] }) });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 4);
    assert.ok(codes(envelope(run)).includes('no_files_scanned'));
  });

  it('unreadable source: degraded fingerprint, non-authoritative, still complete', async () => {
    const repo = repoWith({ stdout: semgrepOutput({ results: [semgrepResult({ path: 'src/missing.js' })] }) });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 0, run.stderr);
    const env = envelope(run);
    assert.equal(env.status, 'complete');
    assert.equal(env.authoritative, false);
    assert.ok(env.non_authoritative_reasons.includes('fingerprint_degraded'));
    assert.ok(codes(env).includes('fingerprint_degraded'));
    const dir = assertContract(run, repo) as string;
    assert.equal(readJson(join(dir, 'normalized.json')).findings[0].fingerprint_quality, 'degraded');
  });

  it('target changed during the scan: partial target_changed_during_scan', async () => {
    const repo = repoWith({
      stdout: semgrepOutput({ results: [semgrepResult()] }),
      mutate: { path: '', content: 'changed\n' },
    });
    const spec = readJson(repo.specPath);
    spec.mutate.path = join(repo.root, 'src', 'other.js');
    writeFileSync(repo.specPath, JSON.stringify(spec));
    writeFileSync(join(repo.root, 'src', 'other.js'), 'original\n');
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 4);
    const env = envelope(run);
    assert.equal(env.status, 'partial');
    assert.ok(codes(env).includes('target_changed_during_scan'));
  });
});

describe('semgrep scan: rule modes', () => {
  it('registry ids: non-authoritative, metrics flag omitted, digest null', async () => {
    const repo = repoWith({ stdout: semgrepOutput() }, { 'src/app.js': SOURCE_LINES }, configYaml({ semgrepConfig: '      registry_ids: ["p/ci"]\n' }));
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 0, run.stderr);
    const env = envelope(run);
    assert.equal(env.authoritative, false);
    assert.deepEqual(env.non_authoritative_reasons, ['registry_rules']);
    assert.ok(codes(env).includes('non_deterministic_rules'));
    const scanArgv = semgrepArgv(repo).find((a) => a[0] === 'scan') as string[];
    assert.ok(scanArgv.join(' ').includes('--config p/ci'));
    assert.ok(!scanArgv.includes('--metrics=off'));
    const dir = scanDirectory(repo) as string;
    assert.equal(readJson(join(dir, 'normalized.json')).rules_digest, null);
  });

  it('auto: non-authoritative auto_rules', async () => {
    const repo = repoWith({ stdout: semgrepOutput() }, { 'src/app.js': SOURCE_LINES }, configYaml({ semgrepConfig: '      use_auto: true\n' }));
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 0, run.stderr);
    const env = envelope(run);
    assert.deepEqual(env.non_authoritative_reasons, ['auto_rules']);
    const scanArgv = semgrepArgv(repo).find((a) => a[0] === 'scan') as string[];
    assert.ok(scanArgv.join(' ').includes('--config auto'));
  });

  it('local rules: authoritative with the pinned argv', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    await runCli(repo, SCAN);
    const scanArgv = semgrepArgv(repo).find((a) => a[0] === 'scan') as string[];
    assert.deepEqual(scanArgv.slice(0, 5), ['scan', '--json', '--metrics=off', '--disable-version-check', '--disable-nosem']);
    assert.ok(scanArgv.includes('rules/security.yaml'));
  });
});

describe('semgrep scan: output directory', () => {
  it('descendant of the target is excluded from argv and recorded, without making the scan partial', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 0);
    const env = envelope(run);
    assert.equal(env.status, 'complete');
    assert.deepEqual(env.exclusions, [{ path: 'out', reason: 'output_directory' }]);
    const scanArgv = semgrepArgv(repo).find((a) => a[0] === 'scan') as string[];
    const at = scanArgv.indexOf('--exclude');
    assert.equal(scanArgv[at + 1], 'out');
  });

  it('previous-run artifacts never change the digest and are never rescanned', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const first = await runCli(repo, SCAN);
    const second = await runCli(repo, SCAN);
    assert.equal(first.status, 0);
    assert.equal(second.status, 0);
    const dirs = readdirSync(join(repo.root, 'out'));
    assert.equal(dirs.length, 2);
    const digests = dirs.map((d) => readJson(join(repo.root, 'out', d, 'normalized.json')).target.content_digest);
    assert.equal(digests[0], digests[1]);
    for (const argv of semgrepArgv(repo).filter((a) => a[0] === 'scan')) assert.ok(argv.includes('--exclude'));
  });

  it('sibling and outside output directories are not excluded', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const sibling = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out']);
    assert.equal(envelope(sibling).exclusions.length, 0);
    const outside = tempDir('scanbridge-out-');
    const other = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', outside]);
    assert.equal(other.status, 0, other.stderr);
    assert.deepEqual(envelope(other).exclusions, []);
    for (const argv of semgrepArgv(repo).filter((a) => a[0] === 'scan')) assert.ok(!argv.includes('--exclude'));
  });

  it('an ancestor output directory (target inside output) is not excluded', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const run = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', '.']);
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(envelope(run).exclusions, []);
  });

  it('output equal to the target and a file output are usage errors', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const equal = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'src']);
    assert.equal(equal.status, 1);
    assert.equal(JSON.parse(equal.stdout).error.code, 'usage_error');
    const file = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'src/app.js']);
    assert.equal(file.status, 1);
  });

  it('creates a missing output base', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    const run = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'deep/new/base']);
    assert.equal(run.status, 0, run.stderr);
    assert.equal(readdirSync(join(repo.root, 'deep', 'new', 'base')).length, 1);
  });

  it('paths stay repository-root-relative when the target is a subdirectory', async () => {
    const repo = repoWith({ stdout: semgrepOutput({ results: [semgrepResult()] }) });
    const run = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out']);
    assert.equal(run.status, 0, run.stderr);
    const dir = scanDirectory(repo) as string;
    const normalized = readJson(join(dir, 'normalized.json'));
    assert.equal(normalized.findings[0].occurrences[0].source_location.path, 'src/app.js');
    assert.equal(normalized.target.relative_path, 'src');
  });
});

describe('semgrep scan: usage', () => {
  it('a disabled adapter is a usage error', async () => {
    const repo = repoWith({ stdout: semgrepOutput() }, { 'src/app.js': SOURCE_LINES }, configYaml({ semgrepEnabled: false }));
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 1);
    assert.equal(JSON.parse(run.stdout).error.code, 'usage_error');
    assert.equal(existsSync(join(repo.root, 'out')), false);
  });

  it('a target outside the root or missing is a usage error', async () => {
    const repo = repoWith({ stdout: semgrepOutput() });
    mkdirSync(join(repo.root, 'x'));
    const missing = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'nope', '--output', 'out']);
    assert.equal(missing.status, 1);
    const outside = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', tempDir('scanbridge-outside-'), '--output', 'out']);
    assert.equal(outside.status, 1);
  });

  it('an invalid configuration is exit 1 with an error envelope', async () => {
    const repo = repoWith({ stdout: semgrepOutput() }, { 'src/app.js': SOURCE_LINES }, 'version: 2\n');
    const run = await runCli(repo, SCAN);
    assert.equal(run.status, 1);
    assert.equal(JSON.parse(run.stdout).error.code, 'invalid_configuration');
  });
});
