import type { ScanArgs } from '../args.js';
import type { CliDeps } from '../main.js';
import { runScan as run } from '../scan/run.js';

/** Replaces the T13 stub: every valid `scan` invocation lands here. */
export function runScan(args: ScanArgs, deps: CliDeps): Promise<{ exitCode: number; output: string }> {
  return run(args, deps);
}
