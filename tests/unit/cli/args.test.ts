import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseCli } from '../../../src/cli/args.js';

const ok = (argv: string[]) => {
  const result = parseCli(argv);
  assert.equal(result.ok, true, `expected valid: ${argv.join(' ')} -> ${JSON.stringify(result)}`);
  return result.ok ? result.value : undefined;
};

const usage = (argv: string[]) => {
  const result = parseCli(argv);
  assert.equal(result.ok, false, `expected usage error: ${argv.join(' ')}`);
};

describe('command selection', () => {
  it('rejects a missing or unknown command', () => {
    usage([]);
    usage(['bogus']);
    usage(['--help']);
  });
});

describe('doctor', () => {
  it('defaults the config path and accepts --json', () => {
    assert.deepEqual(ok(['doctor']), { command: 'doctor', config: '.pr-review/tools.yaml' });
    assert.deepEqual(ok(['doctor', '--config', 'x.yaml', '--json']), { command: 'doctor', config: 'x.yaml' });
  });

  it('rejects unknown flags, positionals, missing or repeated values and empty values', () => {
    usage(['doctor', '--nope']);
    usage(['doctor', 'extra']);
    usage(['doctor', '--config']);
    usage(['doctor', '--config', 'a', '--config', 'b']);
    usage(['doctor', '--config', '']);
    usage(['doctor', '--json', '--json']);
    usage(['doctor', '--json=yes']);
    usage(['doctor', '--allow-partial']);
    usage(['doctor', '--target', 'src']);
  });
});

describe('compare', () => {
  it('requires both reports and accepts --allow-partial and --json', () => {
    assert.deepEqual(ok(['compare', '--base-report', 'a.json', '--head-report', 'b.json']), {
      command: 'compare',
      baseReport: 'a.json',
      headReport: 'b.json',
      allowPartial: false,
    });
    assert.deepEqual(ok(['compare', '--base-report', 'a', '--head-report', 'b', '--allow-partial', '--json']), {
      command: 'compare',
      baseReport: 'a',
      headReport: 'b',
      allowPartial: true,
    });
  });

  it('rejects a missing report, unknown flags and scan-only flags', () => {
    usage(['compare', '--base-report', 'a']);
    usage(['compare', '--head-report', 'b']);
    usage(['compare', '--base-report', 'a', '--head-report', 'b', '--config', 'c']);
    usage(['compare', '--base-report', 'a', '--head-report', 'b', '--output', 'o']);
    usage(['compare', '--base-report', '', '--head-report', 'b']);
  });
});

describe('scan --adapter semgrep', () => {
  it('requires --target and --output and accepts --config', () => {
    assert.deepEqual(ok(['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out']), {
      command: 'scan',
      adapter: 'semgrep',
      target: 'src',
      output: 'out',
      config: '.pr-review/tools.yaml',
    });
    assert.deepEqual(ok(['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out', '--config', 'c.yaml']), {
      command: 'scan',
      adapter: 'semgrep',
      target: 'src',
      output: 'out',
      config: 'c.yaml',
    });
  });

  it('rejects missing target or output', () => {
    usage(['scan', '--adapter', 'semgrep', '--output', 'o']);
    usage(['scan', '--adapter', 'semgrep', '--target', 't']);
  });

  it('rejects every flag that belongs to zap', () => {
    for (const extra of [
      ['--target-url', 'http://127.0.0.1:8080'],
      ['--from-report', 'f.json'],
      ['--target-revision', 'rev'],
      ['--producer-version', '1.0'],
    ]) {
      usage(['scan', '--adapter', 'semgrep', '--target', 't', '--output', 'o', ...extra]);
    }
  });
});

describe('scan --adapter zap', () => {
  it('accepts live mode with or without --target-url (env fallback)', () => {
    assert.deepEqual(ok(['scan', '--adapter', 'zap', '--output', 'o']), {
      command: 'scan',
      adapter: 'zap',
      targetUrl: undefined,
      fromReport: undefined,
      output: 'o',
      config: '.pr-review/tools.yaml',
      targetRevision: undefined,
      producerVersion: undefined,
    });
    ok(['scan', '--adapter', 'zap', '--target-url', 'http://127.0.0.1:8080/', '--output', 'o', '--target-revision', 'rev']);
  });

  it('accepts offline mode with --from-report, optional target URL, revision and producer version', () => {
    ok(['scan', '--adapter', 'zap', '--from-report', 'f.json', '--output', 'o']);
    ok([
      'scan', '--adapter', 'zap', '--from-report', 'f.json', '--target-url', 'http://127.0.0.1:8080',
      '--output', 'o', '--config', 'c.yaml', '--target-revision', 'rev', '--producer-version', '2.10.0',
    ]);
  });

  it('rejects --target, --producer-version in live mode, and a missing output', () => {
    usage(['scan', '--adapter', 'zap', '--target', 'src', '--output', 'o']);
    usage(['scan', '--adapter', 'zap', '--target', 'src', '--from-report', 'f', '--output', 'o']);
    usage(['scan', '--adapter', 'zap', '--producer-version', '1.0', '--output', 'o']);
    usage(['scan', '--adapter', 'zap']);
  });

  it('validates --target-revision and --producer-version characters and length (≤128)', () => {
    const accepted = ['rev', 'v1.2.3+build/x@y:z-', 'a'.repeat(128)];
    for (const value of accepted) {
      ok(['scan', '--adapter', 'zap', '--output', 'o', '--target-revision', value]);
      ok(['scan', '--adapter', 'zap', '--from-report', 'f', '--output', 'o', '--producer-version', value]);
    }
    const rejected = ['a'.repeat(129), 'has space', 'bad!char', 'semi;colon', 'new\nline'];
    for (const value of rejected) {
      usage(['scan', '--adapter', 'zap', '--output', 'o', '--target-revision', value]);
      usage(['scan', '--adapter', 'zap', '--from-report', 'f', '--output', 'o', '--producer-version', value]);
    }
  });
});

describe('scan adapter selection', () => {
  it('rejects a missing or unknown adapter', () => {
    usage(['scan', '--output', 'o']);
    usage(['scan', '--adapter', 'other', '--output', 'o']);
    usage(['scan', '--adapter', 'ZAP', '--output', 'o']);
  });

  it('rejects an empty output path', () => {
    usage(['scan', '--adapter', 'zap', '--output', '']);
  });
});
