import { mkdir, open, realpath, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256Hex } from '../../core/fingerprints/hash.js';

const SCAN_ID = /^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z-[0-9a-f]{8}$/;
const RAW_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/;

export const NORMALIZED_FILE = 'normalized.json';
export const SCAN_RESULT_FILE = 'scan-result.json';

/** What was persisted: path relative to the scan directory, exact byte count and SHA-256 of those bytes. */
export interface StoredArtifact {
  relativePath: string;
  bytes: number;
  sha256: string;
}

export class ScanDirectoryExistsError extends Error {
  readonly code = 'scan_directory_exists';
}

export class ArtifactExistsError extends Error {
  readonly code = 'artifact_exists';
}

export class EmptyArtifactError extends Error {
  readonly code = 'empty_artifact';
}

/**
 * The only module that writes report artifacts (spec 02). Every write is exclusive (`wx`), so an
 * existing file is never overwritten, and empty content is refused before anything touches disk.
 */
export class ReportStore {
  readonly directory: string;

  private constructor(directory: string) {
    this.directory = directory;
  }

  /**
   * Creates a missing base, then the scan directory non-recursively. Writes go under the real
   * base path, so symlinks are resolved once here; an existing scan directory is an error.
   */
  static async createScanDirectory(outputBase: string, scanId: string): Promise<ReportStore> {
    if (!SCAN_ID.test(scanId)) throw new TypeError(`createScanDirectory: invalid scan id "${scanId}"`);
    await mkdir(outputBase, { recursive: true });
    const base = await realpath(outputBase);
    if (!(await stat(base)).isDirectory()) throw new TypeError(`createScanDirectory: ${base} is not a directory`);
    const directory = join(base, scanId);
    try {
      await mkdir(directory);
    } catch (error) {
      if (isErrno(error, 'EEXIST')) throw new ScanDirectoryExistsError(`scan directory already exists: ${scanId}`);
      throw error;
    }
    return new ReportStore(directory);
  }

  /** Redacted producer-shaped raw file under `raw/`; `name` is a plain `*.json` file name. */
  async writeRaw(name: string, text: string): Promise<StoredArtifact> {
    if (!RAW_NAME.test(name)) throw new TypeError(`writeRaw: invalid raw file name "${name}"`);
    if (text.length === 0) throw new EmptyArtifactError(`refusing to write empty raw/${name}`);
    const rawDir = join(this.directory, 'raw');
    await mkdir(rawDir, { recursive: true });
    return this.writeExclusive(`raw/${name}`, text);
  }

  async writeNormalized(text: string): Promise<StoredArtifact> {
    return this.writeTopLevel(NORMALIZED_FILE, text);
  }

  async writeScanResult(text: string): Promise<StoredArtifact> {
    return this.writeTopLevel(SCAN_RESULT_FILE, text);
  }

  private async writeTopLevel(name: string, text: string): Promise<StoredArtifact> {
    if (text.length === 0) throw new EmptyArtifactError(`refusing to write empty ${name}`);
    return this.writeExclusive(name, text);
  }

  private async writeExclusive(relativePath: string, text: string): Promise<StoredArtifact> {
    const bytes = Buffer.from(text, 'utf8');
    const path = join(this.directory, relativePath);
    let handle;
    try {
      handle = await open(path, 'wx');
    } catch (error) {
      if (isErrno(error, 'EEXIST')) throw new ArtifactExistsError(`artifact already exists: ${relativePath}`);
      throw error;
    }
    try {
      await handle.writeFile(bytes);
      await handle.close();
    } catch (error) {
      await handle.close().catch(() => undefined);
      await rm(path, { force: true });
      throw error;
    }
    return { relativePath, bytes: bytes.length, sha256: sha256Hex(bytes) };
  }
}

function isErrno(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && (error as NodeJS.ErrnoException).code === code;
}
