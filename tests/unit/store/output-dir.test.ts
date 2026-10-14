import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, it } from 'node:test';
import { validateOutputDir } from '../../../src/cli/output-dir.js';

let root: string;
let target: string;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'outdir-')));
  target = join(root, 'target');
  mkdirSync(join(target, 'src'), { recursive: true });
  writeFileSync(join(target, 'src', 'a.ts'), 'x\n');
});

const check = (output: string) => validateOutputDir({ root, output, target: 'target' });

describe('validateOutputDir', () => {
  it('rejects a path that is a file', async () => {
    writeFileSync(join(root, 'file.txt'), 'x');
    assert.deepEqual(await check('file.txt'), { ok: false, error: 'not_a_directory' });
  });

  it('rejects a base whose ancestor is a file', async () => {
    writeFileSync(join(root, 'file.txt'), 'x');
    assert.deepEqual(await check('file.txt/child'), { ok: false, error: 'not_a_directory' });
  });

  it('rejects the target itself', async () => {
    assert.deepEqual(await check('target'), { ok: false, error: 'equals_target' });
    assert.deepEqual(await check('target/../target'), { ok: false, error: 'equals_target' });
  });

  it('excludes a strict descendant of the target by normalized relative path', async () => {
    assert.deepEqual(await check('target/reports'), {
      ok: true,
      outputBase: join(target, 'reports'),
      excludeRelToTarget: 'reports',
    });
    assert.deepEqual(await check('target/a/b/out'), {
      ok: true,
      outputBase: join(target, 'a', 'b', 'out'),
      excludeRelToTarget: 'a/b/out',
    });
  });

  it('excludes a descendant reached through a symlink, by its real target-relative path', async () => {
    symlinkSync(join(target, 'src'), join(root, 'link'));
    const result = await validateOutputDir({ root, output: 'link', target: 'target' });
    assert.deepEqual(result, { ok: true, outputBase: join(target, 'src'), excludeRelToTarget: 'src' });
  });

  it('does not exclude a sibling of the target', async () => {
    assert.deepEqual(await check('sibling'), {
      ok: true,
      outputBase: join(root, 'sibling'),
      excludeRelToTarget: null,
    });
    assert.ok(statSync(join(root, 'sibling')).isDirectory());
  });

  it('does not exclude an ancestor of the target', async () => {
    assert.deepEqual(await check('.'), { ok: true, outputBase: root, excludeRelToTarget: null });
  });

  it('does not exclude an unrelated directory outside the root', async () => {
    const outside = realpathSync(mkdtempSync(join(tmpdir(), 'elsewhere-')));
    const result = await validateOutputDir({ root, output: join(outside, 'out'), target: 'target' });
    assert.deepEqual(result, { ok: true, outputBase: join(outside, 'out'), excludeRelToTarget: null });
  });

  it('creates a missing base, including nested directories', async () => {
    const result = await check('new/nested/out');
    assert.deepEqual(result, {
      ok: true,
      outputBase: join(root, 'new', 'nested', 'out'),
      excludeRelToTarget: null,
    });
    assert.ok(statSync(join(root, 'new', 'nested', 'out')).isDirectory());
  });

  it('resolves a symlinked base that stays inside the root', async () => {
    mkdirSync(join(root, 'real-out'));
    symlinkSync(join(root, 'real-out'), join(root, 'out-link'));
    assert.deepEqual(await check('out-link'), {
      ok: true,
      outputBase: join(root, 'real-out'),
      excludeRelToTarget: null,
    });
  });

  it('rejects a symlinked base that points outside the root', async () => {
    const outside = realpathSync(mkdtempSync(join(tmpdir(), 'escape-')));
    symlinkSync(outside, join(root, 'escape-link'));
    assert.deepEqual(await check('escape-link'), { ok: false, error: 'symlink_escape' });
  });

  it('rejects a dangling symlink as an escape', async () => {
    symlinkSync(join(root, 'missing'), join(root, 'dangling'));
    assert.deepEqual(await check('dangling'), { ok: false, error: 'symlink_escape' });
  });

  it('returns no exclusion when no target is given', async () => {
    const result = await validateOutputDir({ root, output: 'target/reports' });
    assert.deepEqual(result, { ok: true, outputBase: join(target, 'reports'), excludeRelToTarget: null });
  });
});
