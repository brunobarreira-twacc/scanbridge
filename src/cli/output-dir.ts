import { lstat, mkdir, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export type OutputDirError = 'not_a_directory' | 'equals_target' | 'symlink_escape';

export type OutputDirResult =
  | { ok: true; outputBase: string; excludeRelToTarget: string | null }
  | { ok: false; error: OutputDirError };

/**
 * Validates `--output` (spec 03). Relative paths resolve against `root`; a missing base is created.
 * `symlink_escape`: the base lies under `root` by name but its real location is outside `root`.
 * `excludeRelToTarget` is the POSIX target-relative path when output is a strict descendant of
 * `target`, else null. Caller maps every error to exit 1.
 */
export async function validateOutputDir({
  root,
  output,
  target,
}: {
  root: string;
  output: string;
  target?: string;
}): Promise<OutputDirResult> {
  const lexical = resolve(root, output);
  const realRoot = await realpath(root);

  const existing = await statOrNull(lexical);
  if (existing === null) {
    if (await isDanglingSymlink(lexical)) return { ok: false, error: 'symlink_escape' };
    try {
      await mkdir(lexical, { recursive: true });
    } catch (error) {
      if (isErrno(error, 'ENOTDIR') || isErrno(error, 'EEXIST')) return { ok: false, error: 'not_a_directory' };
      throw error;
    }
  } else if (!existing.isDirectory()) {
    return { ok: false, error: 'not_a_directory' };
  }

  const outputBase = await realpath(lexical);
  if (isInside(resolve(root), lexical) && !isInsideOrEqual(realRoot, outputBase)) {
    return { ok: false, error: 'symlink_escape' };
  }

  if (target === undefined) return { ok: true, outputBase, excludeRelToTarget: null };

  const realTarget = await realpath(resolve(root, target));
  if (outputBase === realTarget) return { ok: false, error: 'equals_target' };
  const excludeRelToTarget = isInside(realTarget, outputBase)
    ? relative(realTarget, outputBase).split(sep).join('/')
    : null;
  return { ok: true, outputBase, excludeRelToTarget };
}

async function statOrNull(path: string) {
  try {
    return await stat(path);
  } catch (error) {
    // ENOTDIR: an ancestor is a file; mkdir then reports it as not_a_directory.
    if (isErrno(error, 'ENOENT') || isErrno(error, 'ENOTDIR')) return null;
    throw error;
  }
}

async function isDanglingSymlink(path: string): Promise<boolean> {
  try {
    return (await lstat(path)).isSymbolicLink();
  } catch {
    return false;
  }
}

/** Strict descendant of `parent`. */
function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel !== '' && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`);
}

function isInsideOrEqual(parent: string, child: string): boolean {
  return child === parent || isInside(parent, child);
}

function isErrno(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && (error as NodeJS.ErrnoException).code === code;
}
