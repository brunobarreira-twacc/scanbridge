import { parseArgs } from 'node:util';

export const DEFAULT_CONFIG_PATH = '.pr-review/tools.yaml';

/** Spec 03: `--target-revision` and `--producer-version` share one character and length rule. */
const VERSION_PATTERN = /^[A-Za-z0-9._/@:+-]{1,128}$/;

export type DoctorArgs = { command: 'doctor'; config: string };
export type CompareArgs = { command: 'compare'; baseReport: string; headReport: string; allowPartial: boolean };
export type ScanArgs =
  | { command: 'scan'; adapter: 'semgrep'; target: string; output: string; config: string }
  | {
      command: 'scan';
      adapter: 'zap';
      targetUrl: string | undefined;
      fromReport: string | undefined;
      output: string;
      config: string;
      targetRevision: string | undefined;
      producerVersion: string | undefined;
    };
export type CliCommand = DoctorArgs | CompareArgs | ScanArgs;

export type ArgsResult = { ok: true; value: CliCommand } | { ok: false; message: string };

const COMMON = {
  config: { type: 'string' },
  json: { type: 'boolean' },
} as const;

const OPTIONS = {
  doctor: { config: COMMON.config, json: COMMON.json },
  compare: {
    'base-report': { type: 'string' },
    'head-report': { type: 'string' },
    'allow-partial': { type: 'boolean' },
    json: COMMON.json,
  },
  scan: {
    adapter: { type: 'string' },
    target: { type: 'string' },
    'target-url': { type: 'string' },
    'from-report': { type: 'string' },
    output: { type: 'string' },
    config: COMMON.config,
    'target-revision': { type: 'string' },
    'producer-version': { type: 'string' },
  },
} as const;

type Command = keyof typeof OPTIONS;
type Values = Record<string, string | boolean | undefined>;

/**
 * Parses `argv` (without the node and script entries) in strict mode, then checks the per-command
 * flag matrix from spec 03. Messages are Scanbridge-authored and never echo the argument values.
 */
export function parseCli(argv: readonly string[]): ArgsResult {
  const [name, ...rest] = argv;
  if (!isCommand(name)) return usage('unknown or missing command');
  const parsed = parseStrict(name, rest);
  if (parsed === null) return usage('invalid arguments');
  if (!noDuplicates(parsed.tokens)) return usage('an option was given more than once');
  const values = parsed.values;
  switch (name) {
    case 'doctor':
      return doctorArgs(values);
    case 'compare':
      return compareArgs(values);
    case 'scan':
      return scanArgs(values);
  }
}

/** Strict `util.parseArgs` for one command; `null` on any unknown option, missing value or positional. */
function parseStrict(
  name: Command,
  args: readonly string[],
): { values: Values; tokens: readonly { kind: string; name?: string }[] } | null {
  try {
    const result = parseArgs({ args, options: OPTIONS[name], strict: true, allowPositionals: false, tokens: true });
    // Option names come from OPTIONS[name], so every key is one this command declares.
    return { values: result.values as Values, tokens: result.tokens ?? [] };
  } catch {
    return null;
  }
}

function isCommand(name: string | undefined): name is Command {
  return name === 'doctor' || name === 'compare' || name === 'scan';
}

function noDuplicates(tokens: readonly { kind: string; name?: string }[]): boolean {
  const seen = new Set<string>();
  for (const token of tokens) {
    if (token.kind !== 'option' || token.name === undefined) continue;
    if (seen.has(token.name)) return false;
    seen.add(token.name);
  }
  return true;
}

function doctorArgs(values: Values): ArgsResult {
  const config = nonEmpty(values.config, '--config');
  if (!config.ok) return config;
  return { ok: true, value: { command: 'doctor', config: config.value ?? DEFAULT_CONFIG_PATH } };
}

function compareArgs(values: Values): ArgsResult {
  const base = nonEmpty(values['base-report'], '--base-report');
  if (!base.ok) return base;
  const head = nonEmpty(values['head-report'], '--head-report');
  if (!head.ok) return head;
  if (base.value === undefined) return usage('compare requires --base-report');
  if (head.value === undefined) return usage('compare requires --head-report');
  return {
    ok: true,
    value: {
      command: 'compare',
      baseReport: base.value,
      headReport: head.value,
      allowPartial: values['allow-partial'] === true,
    },
  };
}

function scanArgs(values: Values): ArgsResult {
  const adapter = values.adapter;
  if (adapter === undefined) return usage('scan requires --adapter');
  if (adapter !== 'semgrep' && adapter !== 'zap') return usage('--adapter must be semgrep or zap');
  const picked = pickStrings(values, [
    'target',
    'target-url',
    'from-report',
    'output',
    'config',
    'target-revision',
    'producer-version',
  ]);
  if (!picked.ok) return picked;
  const v = picked.value;
  if (v.output === undefined) return usage('scan requires --output');
  const config = v.config ?? DEFAULT_CONFIG_PATH;

  if (adapter === 'semgrep') {
    if (v.target === undefined) return usage('scan --adapter semgrep requires --target');
    for (const flag of ['target-url', 'from-report', 'target-revision', 'producer-version'] as const) {
      if (v[flag] !== undefined) return usage(`--${flag} is not valid for semgrep`);
    }
    return { ok: true, value: { command: 'scan', adapter, target: v.target, output: v.output, config } };
  }

  if (v.target !== undefined) return usage('--target is not valid for zap');
  const offline = v['from-report'] !== undefined;
  if (!offline && v['producer-version'] !== undefined) {
    return usage('--producer-version is only valid with --from-report');
  }
  for (const flag of ['target-revision', 'producer-version'] as const) {
    const value = v[flag];
    if (value !== undefined && !VERSION_PATTERN.test(value)) return usage(`--${flag} is not a valid value`);
  }
  return {
    ok: true,
    value: {
      command: 'scan',
      adapter,
      targetUrl: v['target-url'],
      fromReport: v['from-report'],
      output: v.output,
      config,
      targetRevision: v['target-revision'],
      producerVersion: v['producer-version'],
    },
  };
}

/** Returns the string-valued options; an empty value is a usage error. */
function pickStrings(
  values: Values,
  names: readonly string[],
): { ok: true; value: Record<string, string | undefined> } | { ok: false; message: string } {
  const out: Record<string, string | undefined> = {};
  for (const name of names) {
    const value = values[name];
    if (value === undefined) continue;
    if (typeof value !== 'string' || value === '') return usage(`--${name} must not be empty`);
    out[name] = value;
  }
  return { ok: true, value: out };
}

function nonEmpty(
  value: string | boolean | undefined,
  flag: string,
): { ok: true; value: string | undefined } | { ok: false; message: string } {
  if (value === undefined) return { ok: true, value: undefined };
  if (typeof value !== 'string' || value === '') return usage(`${flag} must not be empty`);
  return { ok: true, value };
}

function usage(message: string): { ok: false; message: string } {
  return { ok: false, message };
}
