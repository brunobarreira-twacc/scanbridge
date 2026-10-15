import { createHash } from 'node:crypto';
import { createReadStream, type Dirent } from 'node:fs';
import { lstat, readdir, readlink } from 'node:fs/promises';
import { join, posix } from 'node:path';
import type { RawDiagnostic } from '../../contracts/adapter.js';
import { PATH_MAX, TARGET_DIGEST_WALK_MAX_FILES } from '../../contracts/limits.js';
import type { Runner, TargetIdentityReader } from '../../contracts/ports.js';
import { canonicalJson, sha256Hex, type CanonicalJson } from '../../core/fingerprints/index.js';

type Identity = Awaited<ReturnType<TargetIdentityReader['read']>>;
type Failure = 'walk_cap' | 'listing' | 'unreadable';
type Listing = { ok: true; paths: string[] } | { ok: false; reason: Failure };

export type TargetIdentityOptions = {
  rootAbs: string;
  runner: Runner;
  /** Timeout for each `git` call. No limit for it exists in `limits.ts`; the integrator supplies it. */
  gitTimeoutMs: number;
  /** Injectable for tests; defaults to the spec 04 walk limit. */
  walkCap?: number;
};

const DIAGNOSTIC_MESSAGE: Record<Failure, string> = {
  walk_cap: 'target digest walk limit exceeded',
  listing: 'target file listing unavailable',
  unreadable: 'target entry could not be read',
};

/**
 * Target revision, dirty state and content digest. Git targets (detected through `Runner`) list files with
 * `git ls-files`; other directories are walked. Symlinks are hashed by link text and never followed.
 */
export class FsTargetIdentityReader implements TargetIdentityReader {
  readonly #rootAbs: string;
  readonly #runner: Runner;
  readonly #gitTimeoutMs: number;
  readonly #walkCap: number;
  readonly #listingMaxBytes: number;

  constructor(o: TargetIdentityOptions) {
    this.#rootAbs = o.rootAbs;
    this.#runner = o.runner;
    this.#gitTimeoutMs = o.gitTimeoutMs;
    this.#walkCap = o.walkCap ?? TARGET_DIGEST_WALK_MAX_FILES;
    // Each listed path is at most PATH_MAX code points (4 bytes each in UTF-8) plus its NUL separator.
    this.#listingMaxBytes = (this.#walkCap + 1) * (PATH_MAX * 4 + 1);
  }

  async read(o: { targetRel: string; excludeRel: string[] }): Promise<Identity> {
    const targetRel = posix.normalize(o.targetRel);
    const exclude = o.excludeRel.map((rel) => posix.normalize(rel));
    const targetAbs = join(this.#rootAbs, targetRel);

    const inside = await this.#git(['rev-parse', '--is-inside-work-tree']);
    if (!inside.ok || inside.stdout.trim() !== 'true') {
      const listing = await this.#walk(targetAbs, exclude);
      const digest = await this.#digest(targetAbs, listing);
      return { kind: 'directory', relative_path: targetRel, revision: null, dirty: null, ...digest };
    }

    const diagnostics: RawDiagnostic[] = [];
    const head = await this.#git(['rev-parse', 'HEAD']);
    const status = await this.#git(['status', '--porcelain', '--', targetRel]);
    const revision = head.ok && head.stdout.trim() !== '' ? head.stdout.trim() : null;
    const dirty = status.ok ? status.stdout.trim() !== '' : null;
    if (revision === null || dirty === null) {
      diagnostics.push(unavailable('git revision or dirty state unavailable'));
    }

    const listed = await this.#gitListing(targetRel, exclude);
    const digest = await this.#digest(targetAbs, listed);
    return {
      kind: 'git',
      relative_path: targetRel,
      revision,
      dirty,
      content_digest: digest.content_digest,
      diagnostics: [...diagnostics, ...digest.diagnostics],
    };
  }

  async #git(args: string[]): Promise<{ ok: true; stdout: string } | { ok: false }> {
    const r = await this.#runner.run('git', ['--literal-pathspecs', ...args], {
      cwd: this.#rootAbs,
      timeoutMs: this.#gitTimeoutMs,
      maxStdoutBytes: this.#listingMaxBytes,
    });
    if (r.spawnFailed || r.timedOut || r.stdoutTruncated || r.exitCode !== 0) return { ok: false };
    return { ok: true, stdout: Buffer.from(r.stdout).toString('utf8') };
  }

  async #gitListing(targetRel: string, exclude: string[]): Promise<Listing> {
    const listed = await this.#git(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', targetRel]);
    if (!listed.ok) return { ok: false, reason: 'listing' };
    // `ls-files` prints paths relative to the working directory (the root), so strip the target prefix.
    const prefix = targetRel === '.' ? '' : `${targetRel}/`;
    const paths: string[] = [];
    for (const entry of listed.stdout.split('\0')) {
      if (entry === '' || !entry.startsWith(prefix)) continue;
      const rel = entry.slice(prefix.length);
      if (!this.#excluded(rel, exclude)) paths.push(rel);
    }
    return { ok: true, paths };
  }

  /** Directory walk. Stops as soon as the cap is exceeded. */
  async #walk(targetAbs: string, exclude: string[]): Promise<Listing> {
    const paths: string[] = [];
    const visit = async (relDir: string): Promise<Failure | null> => {
      let entries: Dirent[];
      try {
        entries = await readdir(join(targetAbs, relDir), { withFileTypes: true });
      } catch {
        return 'unreadable';
      }
      for (const entry of entries) {
        const rel = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
        if (this.#excluded(rel, exclude)) continue;
        // Symlinks are `isDirectory() === false`, so they are recorded and never descended into.
        if (entry.isDirectory()) {
          const failed = await visit(rel);
          if (failed !== null) return failed;
          continue;
        }
        paths.push(rel);
        if (paths.length > this.#walkCap) return 'walk_cap';
      }
      return null;
    };
    const failed = await visit('');
    return failed === null ? { ok: true, paths } : { ok: false, reason: failed };
  }

  async #digest(
    targetAbs: string,
    listing: Listing,
  ): Promise<{ content_digest: string | null; diagnostics: RawDiagnostic[] }> {
    if (!listing.ok) return { content_digest: null, diagnostics: [unavailable(DIAGNOSTIC_MESSAGE[listing.reason])] };
    if (listing.paths.length > this.#walkCap) {
      return { content_digest: null, diagnostics: [unavailable(DIAGNOSTIC_MESSAGE.walk_cap)] };
    }

    const records: CanonicalJson[][] = [];
    for (const rel of listing.paths) {
      try {
        records.push(await record(join(targetAbs, ...rel.split('/')), rel));
      } catch {
        return { content_digest: null, diagnostics: [unavailable(DIAGNOSTIC_MESSAGE.unreadable)] };
      }
    }
    records.sort((a, b) => compare(a[0] as string, b[0] as string));
    return { content_digest: sha256Hex(canonicalJson(records)), diagnostics: [] };
  }

  #excluded(rel: string, exclude: string[]): boolean {
    if (rel.split('/').includes('.git')) return true;
    return exclude.some((base) => rel === base || rel.startsWith(`${base}/`));
  }
}

/** `[path, entry type, executable bit, content SHA-256]` for one entry; throws if it cannot be read. */
async function record(abs: string, rel: string): Promise<CanonicalJson[]> {
  const stat = await lstat(abs);
  if (stat.isSymbolicLink()) return [rel, 'symlink', false, sha256Hex(await readlink(abs))];
  if (stat.isFile()) return [rel, 'file', (stat.mode & 0o100) !== 0, await fileSha256(abs)];
  throw new Error('unsupported entry type');
}

function fileSha256(abs: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(abs);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function unavailable(message: string): RawDiagnostic {
  return { code: 'target_identity_unavailable', level: 'warn', message };
}
