import { spawn } from 'node:child_process';
import type { RunResult, Runner } from '../../contracts/ports.js';

const PRODUCTION_ALLOWLIST: readonly string[] = ['semgrep', 'git'];
const STDERR_TAIL_BYTES = 2 * 1024;
const KILL_GRACE_MS = 5_000;

type Cmd = Parameters<Runner['run']>[0];

/**
 * Runs allowlisted binaries with a fixed argv and no shell. `spawn` with `shell: false` is used instead of
 * `execFile` because `execFile` buffers all of stdout before its `maxBuffer` kill, so it cannot stop reading
 * at the cap. Nothing is logged.
 */
export class NodeRunner implements Runner {
  readonly #allowlist: readonly string[];
  readonly #killGraceMs: number;

  constructor(allowlist: readonly string[] = PRODUCTION_ALLOWLIST, killGraceMs = KILL_GRACE_MS) {
    this.#allowlist = allowlist;
    this.#killGraceMs = killGraceMs;
  }

  run(cmd: Cmd, args: readonly string[], o: { cwd: string; timeoutMs: number; maxStdoutBytes: number }): Promise<RunResult> {
    if (!this.#allowlist.includes(cmd)) return Promise.resolve(notStarted());

    return new Promise((resolve) => {
      const stdout: Buffer[] = [];
      let stdoutBytes = 0;
      let stdoutTruncated = false;
      let timedOut = false;
      let stderrTail = Buffer.alloc(0);
      let settled = false;
      let killTimer: NodeJS.Timeout | undefined;
      let timeoutTimer: NodeJS.Timeout | undefined;

      const child = spawn(cmd, args, { cwd: o.cwd, shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });

      const terminate = () => {
        child.kill('SIGTERM');
        killTimer ??= setTimeout(() => child.kill('SIGKILL'), this.#killGraceMs);
      };

      const finish = (exitCode: number | null, signal: string | null, spawnFailed: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutTimer);
        clearTimeout(killTimer);
        resolve({
          exitCode,
          signal,
          timedOut,
          spawnFailed,
          stdout: Buffer.concat(stdout),
          stdoutTruncated,
          stderrTail: stderrTail.toString('utf8'),
        });
      };

      timeoutTimer = setTimeout(() => {
        timedOut = true;
        terminate();
      }, o.timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        if (stdoutTruncated) return;
        const room = o.maxStdoutBytes - stdoutBytes;
        if (chunk.length <= room) {
          stdout.push(chunk);
          stdoutBytes += chunk.length;
          return;
        }
        if (room > 0) stdout.push(chunk.subarray(0, room));
        stdoutBytes += Math.max(room, 0);
        stdoutTruncated = true;
        child.stdout.destroy();
        terminate();
      });

      child.stderr.on('data', (chunk: Buffer) => {
        const joined = Buffer.concat([stderrTail, chunk]);
        stderrTail = joined.length > STDERR_TAIL_BYTES ? joined.subarray(joined.length - STDERR_TAIL_BYTES) : joined;
      });

      // `error` before a pid is a spawn failure (for example a missing binary). A later `error` is not.
      child.on('error', () => {
        if (child.pid === undefined) finish(null, null, true);
      });

      // `close` waits for stdio to end. A grandchild holding the pipes must not hang the run, so after `exit`
      // the streams are given the same grace as the kill and then released.
      child.on('exit', (exitCode, signal) => {
        if (settled) return;
        setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
          finish(exitCode, signal, false);
        }, this.#killGraceMs).unref();
      });
      child.on('close', (exitCode, signal) => finish(exitCode, signal, false));
    });
  }
}

function notStarted(): RunResult {
  return {
    exitCode: null,
    signal: null,
    timedOut: false,
    spawnFailed: true,
    stdout: new Uint8Array(0),
    stdoutTruncated: false,
    stderrTail: '',
  };
}
