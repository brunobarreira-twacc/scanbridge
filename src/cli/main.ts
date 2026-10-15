import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import type { Clock, EnvReader, HttpClient, Runner } from '../contracts/ports.js';
import type { ToolCatalog } from '../contracts/adapter.js';
import { parseCli, type CliCommand } from './args.js';
import { runCompare } from './commands/compare.js';
import { runDoctor } from './commands/doctor.js';
import { runScan } from './commands/scan.js';
import { errorEnvelope } from './envelope.js';
import { ERROR_EXIT_CODES } from './exit.js';

export type Sink = { write(chunk: string): unknown };

/** Adapters and process ports. Absent in a build that has not wired them: `doctor` then reports tools unavailable. */
export type CliPorts = { catalog: ToolCatalog; runner: Runner; http: HttpClient };

export type CliDeps = {
  cwd: string;
  env: EnvReader;
  clock: Clock;
  ports?: CliPorts;
  stdout: Sink;
  stderr: Sink;
};

/** Parses `argv` (without node and the script), runs the command, writes one JSON document to stdout, returns the exit code. */
export async function main(argv: readonly string[], deps: CliDeps): Promise<number> {
  const context = { ...deps, cwd: realpathSync(deps.cwd) };
  const parsed = parseCli(argv);
  const outcome = parsed.ok
    ? await dispatch(parsed.value, context)
    : { exitCode: ERROR_EXIT_CODES.usage_error, output: errorEnvelope('usage_error', parsed.message) };
  deps.stdout.write(outcome.output);
  return outcome.exitCode;
}

async function dispatch(command: CliCommand, deps: CliDeps): Promise<{ exitCode: number; output: string }> {
  switch (command.command) {
    case 'doctor':
      return runDoctor(command, deps);
    case 'compare':
      return runCompare(command, deps);
    case 'scan':
      return runScan();
  }
}

// Bin entry: runs only when this module is the executed script, never when a test imports it.
const script = process.argv[1];
if (script !== undefined && import.meta.url === pathToFileURL(realpathSync(script)).href) {
  process.exitCode = await main(process.argv.slice(2), {
    cwd: process.cwd(),
    env: { get: (name) => process.env[name] },
    clock: { now: () => new Date(), sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) },
    stdout: process.stdout,
    stderr: process.stderr,
  });
}
