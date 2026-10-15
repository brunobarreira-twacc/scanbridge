import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, it } from 'node:test';
import { SOURCE_READ_MAX_BYTES } from '../../../src/contracts/limits.js';
import { FsSourceReader } from '../../../src/cli/ports/source-reader.js';

let root: string;
let outside: string;
let reader: FsSourceReader;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'source-')));
  outside = realpathSync(mkdtempSync(join(tmpdir(), 'outside-')));
  mkdirSync(join(root, 'target', 'src'), { recursive: true });
  mkdirSync(join(root, 'target', 'real'), { recursive: true });
  writeFileSync(join(root, 'target', 'src', 'a.ts'), 'one\ntwo\nthree\nfour\n');
  writeFileSync(join(root, 'target', 'real', 'b.ts'), 'bee\n');
  writeFileSync(join(outside, 'secret.ts'), 'secret\n');
  symlinkSync(join(root, 'target', 'src', 'a.ts'), join(root, 'target', 'link.ts'));
  symlinkSync(join(root, 'target', 'real'), join(root, 'target', 'linkdir'));
  symlinkSync(outside, join(root, 'target', 'escape'));
  reader = new FsSourceReader(root, 'target');
});

describe('FsSourceReader', () => {
  it('returns the complete line range joined with LF', async () => {
    assert.deepEqual(await reader.readLines('target/src/a.ts', 2, 3), { ok: true, text: 'two\nthree' });
  });

  it('reads a last line that has no trailing newline', async () => {
    writeFileSync(join(root, 'target', 'src', 'nonl.ts'), 'alpha\nbeta');
    assert.deepEqual(await reader.readLines('target/src/nonl.ts', 1, 2), { ok: true, text: 'alpha\nbeta' });
  });

  it('strips CR from CRLF line endings', async () => {
    writeFileSync(join(root, 'target', 'src', 'crlf.ts'), 'a\r\nb\r\n');
    assert.deepEqual(await reader.readLines('target/src/crlf.ts', 1, 2), { ok: true, text: 'a\nb' });
  });

  it('rejects paths outside the target', async () => {
    writeFileSync(join(root, 'other.ts'), 'x\n');
    assert.deepEqual(await reader.readLines('other.ts', 1, 1), { ok: false, reason: 'outside_target' });
    assert.deepEqual(await reader.readLines('target/../other.ts', 1, 1), { ok: false, reason: 'outside_target' });
    assert.deepEqual(await reader.readLines(join(root, 'target', 'src', 'a.ts'), 1, 1), {
      ok: false,
      reason: 'outside_target',
    });
  });

  it('rejects a symlink file', async () => {
    assert.deepEqual(await reader.readLines('target/link.ts', 1, 1), { ok: false, reason: 'symlink' });
  });

  it('rejects a path through a symlinked directory component', async () => {
    assert.deepEqual(await reader.readLines('target/linkdir/b.ts', 1, 1), { ok: false, reason: 'symlink' });
  });

  it('rejects a path through a symlink that leaves the target', async () => {
    assert.deepEqual(await reader.readLines('target/escape/secret.ts', 1, 1), { ok: false, reason: 'symlink' });
  });

  it('accepts a file one byte under, exactly at, and rejects one byte over 1 MiB', async () => {
    writeFileSync(join(root, 'target', 'src', 'under.ts'), 'a'.repeat(SOURCE_READ_MAX_BYTES - 1));
    assert.deepEqual(await reader.readLines('target/src/under.ts', 1, 1), {
      ok: true,
      text: 'a'.repeat(SOURCE_READ_MAX_BYTES - 1),
    });

    writeFileSync(join(root, 'target', 'src', 'at.ts'), 'a'.repeat(SOURCE_READ_MAX_BYTES));
    const at = await reader.readLines('target/src/at.ts', 1, 1);
    assert.deepEqual(at, { ok: true, text: 'a'.repeat(SOURCE_READ_MAX_BYTES) });

    writeFileSync(join(root, 'target', 'src', 'over.ts'), 'a'.repeat(SOURCE_READ_MAX_BYTES + 1));
    assert.deepEqual(await reader.readLines('target/src/over.ts', 1, 1), { ok: false, reason: 'too_large' });
  });

  it('rejects invalid UTF-8 without repairing it', async () => {
    writeFileSync(join(root, 'target', 'src', 'bad.ts'), Buffer.from([0x61, 0xff, 0x62, 0x0a]));
    assert.deepEqual(await reader.readLines('target/src/bad.ts', 1, 1), { ok: false, reason: 'invalid_utf8' });
  });

  it('reports a missing file', async () => {
    assert.deepEqual(await reader.readLines('target/src/none.ts', 1, 1), { ok: false, reason: 'missing' });
  });

  it('reports changed when the range starts past the end of the file', async () => {
    assert.deepEqual(await reader.readLines('target/src/a.ts', 9, 9), { ok: false, reason: 'changed' });
  });
});
