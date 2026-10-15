import { constants } from 'node:fs';
import { lstat, open, type FileHandle } from 'node:fs/promises';
import { isAbsolute, join, posix } from 'node:path';
import { SOURCE_READ_MAX_BYTES } from '../../contracts/limits.js';
import type { SourceFailure, SourceReader } from '../../contracts/ports.js';

type Read = { ok: true; text: string } | { ok: false; reason: SourceFailure };

/** Reads line ranges of files under `targetRel` below `rootAbs`. Symlinks are never followed. */
export class FsSourceReader implements SourceReader {
  readonly #rootAbs: string;
  readonly #targetRel: string;

  constructor(rootAbs: string, targetRel: string) {
    this.#rootAbs = rootAbs;
    this.#targetRel = posix.normalize(targetRel);
  }

  async readLines(pathFromRoot: string, startLine: number, endLine: number): Promise<Read> {
    const rel = this.#insideTarget(pathFromRoot);
    if (rel === null) return { ok: false, reason: 'outside_target' };

    const chain = await this.#checkChain(rel);
    if (chain !== null) return { ok: false, reason: chain };

    const file = await this.#readBounded(join(this.#rootAbs, ...rel.split('/')));
    if (!file.ok) return file;

    let text: string;
    try {
      // ignoreBOM keeps a byte order mark in the text; the fingerprint canonicalizer removes it.
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(file.bytes);
    } catch {
      return { ok: false, reason: 'invalid_utf8' };
    }

    const lines = text === '' ? [] : text.replace(/\n$/, '').split('\n').map((line) => line.replace(/\r$/, ''));
    if (startLine < 1 || endLine < startLine) return { ok: false, reason: 'unreadable' };
    if (startLine > lines.length) return { ok: false, reason: 'changed' };
    return { ok: true, text: lines.slice(startLine - 1, endLine).join('\n') };
  }

  /** Lexical check only: the normalized root-relative path, or null when it does not lie inside the target. */
  #insideTarget(pathFromRoot: string): string | null {
    if (isAbsolute(pathFromRoot) || pathFromRoot.split('/').includes('..')) return null;
    const rel = posix.normalize(pathFromRoot);
    const prefix = this.#targetRel === '.' ? '' : `${this.#targetRel}/`;
    return rel.startsWith(prefix) && rel.length > prefix.length ? rel : null;
  }

  /** Every component from the root down must exist and be a real entry, never a symlink. */
  async #checkChain(rel: string): Promise<SourceFailure | null> {
    const parts = rel.split('/');
    let current = this.#rootAbs;
    for (const [index, part] of parts.entries()) {
      current = join(current, part);
      const last = index === parts.length - 1;
      let stat;
      try {
        stat = await lstat(current);
      } catch (err) {
        return isMissing(err) ? 'missing' : 'unreadable';
      }
      if (stat.isSymbolicLink()) return 'symlink';
      if (!last && !stat.isDirectory()) return 'missing';
      if (last && !stat.isFile()) return 'unreadable';
    }
    return null;
  }

  async #readBounded(abs: string): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; reason: SourceFailure }> {
    let handle: FileHandle;
    try {
      handle = await open(abs, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (err) {
      if (codeOf(err) === 'ELOOP') return { ok: false, reason: 'symlink' };
      return { ok: false, reason: isMissing(err) ? 'missing' : 'unreadable' };
    }
    try {
      const stat = await handle.stat();
      if (stat.size > SOURCE_READ_MAX_BYTES) return { ok: false, reason: 'too_large' };
      const bytes = await handle.readFile();
      if (bytes.byteLength > SOURCE_READ_MAX_BYTES) return { ok: false, reason: 'too_large' };
      return { ok: true, bytes };
    } catch {
      return { ok: false, reason: 'unreadable' };
    } finally {
      await handle.close();
    }
  }
}

function codeOf(err: unknown): string | undefined {
  return (err as { code?: string } | undefined)?.code;
}

function isMissing(err: unknown): boolean {
  return codeOf(err) === 'ENOENT' || codeOf(err) === 'ENOTDIR';
}
