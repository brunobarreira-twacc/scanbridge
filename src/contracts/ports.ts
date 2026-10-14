import type { RawDiagnostic } from './adapter.js';
import type { SensitiveString } from './sensitive.js';

export type RunResult = {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  spawnFailed: boolean;
  stdout: Uint8Array;
  stdoutTruncated: boolean;
  stderrTail: string;
};

export interface Runner {
  run(
    cmd: 'semgrep' | 'git',
    args: readonly string[],
    o: { cwd: string; timeoutMs: number; maxStdoutBytes: number },
  ): Promise<RunResult>;
}

export type HttpResult =
  | { kind: 'response'; status: number; body: Uint8Array; truncated: boolean }
  | { kind: 'closed' }
  | { kind: 'timeout' }
  | { kind: 'error'; code: string };

/** GET only. */
export interface HttpClient {
  request(r: {
    url: string;
    headers: Record<string, string>;
    sensitiveHeaders?: Record<string, SensitiveString>;
    timeoutMs: number;
    maxBytes: number;
  }): Promise<HttpResult>;
}

export interface Clock {
  now(): Date;
  sleep(ms: number): Promise<void>;
}

export interface EnvReader {
  get(name: string): string | undefined;
}

export type SourceFailure =
  | 'outside_target'
  | 'symlink'
  | 'too_large'
  | 'invalid_utf8'
  | 'missing'
  | 'changed'
  | 'unreadable';

export interface SourceReader {
  readLines(
    pathFromRoot: string,
    startLine: number,
    endLine: number,
  ): Promise<{ ok: true; text: string } | { ok: false; reason: SourceFailure }>;
}

/** After orchestrator redaction. */
export type SourceText = { ok: true; text: string; redacted: boolean } | { ok: false; reason: SourceFailure };

export interface TargetIdentityReader {
  read(o: { targetRel: string; excludeRel: string[] }): Promise<{
    kind: 'git' | 'directory';
    relative_path: string;
    revision: string | null;
    dirty: boolean | null;
    content_digest: string | null;
    diagnostics: RawDiagnostic[];
  }>;
}
