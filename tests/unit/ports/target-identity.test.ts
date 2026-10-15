import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, it } from 'node:test';
import { FsTargetIdentityReader } from '../../../src/cli/ports/target-identity.js';
import type { Runner, RunResult } from '../../../src/contracts/ports.js';

type Reply = Partial<Pick<RunResult, 'exitCode' | 'spawnFailed' | 'timedOut' | 'stdoutTruncated'>> & { stdout?: string };

/** Fake `Runner`: answers by argv (without the leading `--literal-pathspecs`); anything unscripted is "not a repo". */
function fakeGit(replies: Record<string, Reply>) {
  const calls: string[][] = [];
  const runner: Runner = {
    async run(cmd, args) {
      const argv = args.filter((a) => a !== '--literal-pathspecs');
      calls.push([cmd, ...argv]);
      const reply = replies[argv.join(' ')] ?? { exitCode: 128 };
      return {
        exitCode: reply.exitCode ?? 0,
        signal: null,
        timedOut: reply.timedOut ?? false,
        spawnFailed: reply.spawnFailed ?? false,
        stdout: Buffer.from(reply.stdout ?? ''),
        stdoutTruncated: reply.stdoutTruncated ?? false,
        stderrTail: '',
      };
    },
  };
  return { runner, calls };
}

const NOT_A_REPO = { 'rev-parse --is-inside-work-tree': { exitCode: 128 } };
const LISTING = 'ls-files -z --cached --others --exclude-standard -- target';

let root: string;
const target = () => join(root, 'target');

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'identity-')));
  mkdirSync(join(root, 'target', 'src'), { recursive: true });
  writeFileSync(join(root, 'target', 'src', 'a.ts'), 'export const a = 1;\n');
  writeFileSync(join(root, 'target', 'run.sh'), '#!/bin/sh\n');
  chmodSync(join(root, 'target', 'run.sh'), 0o644);
  symlinkSync('src/a.ts', join(root, 'target', 'alias.ts'));
});

const reader = (runner: Runner, walkCap?: number) =>
  new FsTargetIdentityReader({ rootAbs: root, runner, gitTimeoutMs: 5_000, walkCap });

describe('FsTargetIdentityReader directory branch', () => {
  it('reports revision and dirty as null for a non-git directory', async () => {
    const r = await reader(fakeGit(NOT_A_REPO).runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.kind, 'directory');
    assert.equal(r.relative_path, 'target');
    assert.equal(r.revision, null);
    assert.equal(r.dirty, null);
    assert.match(r.content_digest ?? '', /^[0-9a-f]{64}$/);
    assert.deepEqual(r.diagnostics, []);
  });

  it('treats a git failure to spawn as a non-git directory', async () => {
    const { runner } = fakeGit({ 'rev-parse --is-inside-work-tree': { spawnFailed: true, exitCode: 1 } });
    const r = await reader(runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.kind, 'directory');
  });

  it('is stable across runs', async () => {
    const ident = reader(fakeGit(NOT_A_REPO).runner);
    const a = await ident.read({ targetRel: 'target', excludeRel: [] });
    const b = await ident.read({ targetRel: 'target', excludeRel: [] });
    assert.equal(a.content_digest, b.content_digest);
  });

  it('changes with file content', async () => {
    const ident = reader(fakeGit(NOT_A_REPO).runner);
    const before = await ident.read({ targetRel: 'target', excludeRel: [] });
    writeFileSync(join(target(), 'src', 'a.ts'), 'export const a = 2;\n');
    const after = await ident.read({ targetRel: 'target', excludeRel: [] });
    assert.notEqual(before.content_digest, after.content_digest);
  });

  it('changes with the executable bit', async () => {
    const ident = reader(fakeGit(NOT_A_REPO).runner);
    const before = await ident.read({ targetRel: 'target', excludeRel: [] });
    chmodSync(join(target(), 'run.sh'), 0o755);
    const after = await ident.read({ targetRel: 'target', excludeRel: [] });
    assert.notEqual(before.content_digest, after.content_digest);
  });

  it('changes with a symlink target and hashes link text without following it', async () => {
    const ident = reader(fakeGit(NOT_A_REPO).runner);
    const before = await ident.read({ targetRel: 'target', excludeRel: [] });

    rmSync(join(target(), 'alias.ts'));
    symlinkSync('run.sh', join(target(), 'alias.ts'));
    const retargeted = await ident.read({ targetRel: 'target', excludeRel: [] });
    assert.notEqual(before.content_digest, retargeted.content_digest);

    const outside = mkdtempSync(join(tmpdir(), 'outside-'));
    writeFileSync(join(outside, 'x.txt'), 'one');
    rmSync(join(target(), 'alias.ts'));
    symlinkSync(outside, join(target(), 'alias.ts'));
    const first = await ident.read({ targetRel: 'target', excludeRel: [] });
    writeFileSync(join(outside, 'x.txt'), 'two');
    const second = await ident.read({ targetRel: 'target', excludeRel: [] });
    assert.equal(first.content_digest, second.content_digest);
  });

  it('excludes .git and every excluded directory', async () => {
    const ident = reader(fakeGit(NOT_A_REPO).runner);
    const clean = await ident.read({ targetRel: 'target', excludeRel: ['out'] });

    mkdirSync(join(target(), '.git'));
    writeFileSync(join(target(), '.git', 'HEAD'), 'ref: refs/heads/main\n');
    mkdirSync(join(target(), 'out', 'deep'), { recursive: true });
    writeFileSync(join(target(), 'out', 'deep', 'report.json'), '{}');
    const withExcluded = await ident.read({ targetRel: 'target', excludeRel: ['out'] });
    assert.equal(withExcluded.content_digest, clean.content_digest);
  });

  it('does not exclude a sibling whose name starts with an excluded name', async () => {
    const ident = reader(fakeGit(NOT_A_REPO).runner);
    const clean = await ident.read({ targetRel: 'target', excludeRel: ['out'] });
    mkdirSync(join(target(), 'outer'));
    writeFileSync(join(target(), 'outer', 'x.ts'), 'x\n');
    const sibling = await ident.read({ targetRel: 'target', excludeRel: ['out'] });
    assert.notEqual(sibling.content_digest, clean.content_digest);
  });

  it('digests below, at and above the walk cap (three entries in the fixture)', async () => {
    // Fixture entries: src/a.ts, run.sh, alias.ts.
    const below = await reader(fakeGit(NOT_A_REPO).runner, 4).read({ targetRel: 'target', excludeRel: [] });
    const at = await reader(fakeGit(NOT_A_REPO).runner, 3).read({ targetRel: 'target', excludeRel: [] });
    assert.match(below.content_digest ?? '', /^[0-9a-f]{64}$/);
    assert.equal(at.content_digest, below.content_digest);

    const over = await reader(fakeGit(NOT_A_REPO).runner, 2).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(over.content_digest, null);
    assert.equal(over.diagnostics.length, 1);
    assert.equal(over.diagnostics[0]?.code, 'target_identity_unavailable');
    assert.equal(over.diagnostics[0]?.level, 'warn');
  });
});

describe('FsTargetIdentityReader git branch', () => {
  const gitReplies = (status: string, files: string[]): Record<string, Reply> => ({
    'rev-parse --is-inside-work-tree': { stdout: 'true\n' },
    'rev-parse HEAD': { stdout: 'abc123def\n' },
    'status --porcelain -- target': { stdout: status },
    [LISTING]: { stdout: files.map((f) => `${f}\0`).join('') },
  });

  it('reports revision and clean state from git', async () => {
    const { runner, calls } = fakeGit(gitReplies('', ['target/src/a.ts', 'target/run.sh']));
    const r = await reader(runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.kind, 'git');
    assert.equal(r.revision, 'abc123def');
    assert.equal(r.dirty, false);
    assert.deepEqual(r.diagnostics, []);
    assert.ok(calls.some((c) => c.join(' ') === `git ${LISTING}`));
  });

  it('reports dirty when the scoped status is non-empty and scopes it to the target', async () => {
    const { runner, calls } = fakeGit(gitReplies(' M target/src/a.ts\n', ['target/src/a.ts']));
    const r = await reader(runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.dirty, true);
    assert.ok(calls.some((c) => c.join(' ') === 'git status --porcelain -- target'));
  });

  it('keeps only target-scoped paths and matches the directory digest of the same files', async () => {
    const files = ['target/src/a.ts', 'target/run.sh', 'target/alias.ts', 'elsewhere/x.ts'];
    const git = await reader(fakeGit(gitReplies('', files)).runner).read({ targetRel: 'target', excludeRel: [] });
    const dir = await reader(fakeGit(NOT_A_REPO).runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(git.content_digest, dir.content_digest);
  });

  it('excludes listed paths under an excluded directory', async () => {
    mkdirSync(join(target(), 'out'));
    writeFileSync(join(target(), 'out', 'r.json'), '{}');
    const files = ['target/src/a.ts', 'target/run.sh', 'target/alias.ts', 'target/out/r.json'];
    const git = await reader(fakeGit(gitReplies('', files)).runner).read({ targetRel: 'target', excludeRel: ['out'] });
    const dir = await reader(fakeGit(NOT_A_REPO).runner).read({ targetRel: 'target', excludeRel: ['out'] });
    assert.equal(git.content_digest, dir.content_digest);
  });

  it('gives a null digest when the listing exceeds the cap', async () => {
    const files = ['target/src/a.ts', 'target/run.sh', 'target/alias.ts', 'target/b.ts'];
    const r = await reader(fakeGit(gitReplies('', files)).runner, 3).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.content_digest, null);
    assert.equal(r.diagnostics[0]?.code, 'target_identity_unavailable');
  });

  it('gives a null digest when the listing is truncated or fails', async () => {
    const replies = gitReplies('', []);
    replies[LISTING] = { exitCode: 1 };
    const r = await reader(fakeGit(replies).runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.content_digest, null);
    assert.equal(r.diagnostics[0]?.code, 'target_identity_unavailable');
  });

  it('reports a diagnostic and null revision when HEAD cannot be resolved', async () => {
    const replies = gitReplies('', ['target/run.sh']);
    replies['rev-parse HEAD'] = { exitCode: 128 };
    const r = await reader(fakeGit(replies).runner).read({ targetRel: 'target', excludeRel: [] });
    assert.equal(r.revision, null);
    assert.equal(r.dirty, false);
    assert.equal(r.diagnostics[0]?.code, 'target_identity_unavailable');
  });
});
