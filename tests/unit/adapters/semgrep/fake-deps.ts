import type { Deps } from '../../../../src/contracts/adapter.js';
import type { HttpClient, RunResult, Runner } from '../../../../src/contracts/ports.js';

export type RunCall = {
  cmd: string;
  args: readonly string[];
  cwd: string;
  timeoutMs: number;
  maxStdoutBytes: number;
};

export class FakeRunner implements Runner {
  readonly calls: RunCall[] = [];

  constructor(private readonly result: Partial<RunResult> = {}) {}

  async run(cmd: 'semgrep' | 'git', args: readonly string[], o: Parameters<Runner['run']>[2]): Promise<RunResult> {
    this.calls.push({ cmd, args: [...args], ...o });
    return {
      exitCode: 0,
      signal: null,
      timedOut: false,
      spawnFailed: false,
      stdout: new Uint8Array(),
      stdoutTruncated: false,
      stderrTail: '',
      ...this.result,
    };
  }
}

const unusedHttp: HttpClient = {
  request: async () => {
    throw new Error('http is not used by the Semgrep adapter');
  },
};

export function depsWith(runner: Runner): Deps {
  return {
    runner,
    http: unusedHttp,
    clock: { now: () => new Date(0), sleep: async () => {} },
  };
}

export function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
