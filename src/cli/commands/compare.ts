import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { EXIT_CODES } from '../../contracts/enums.js';
import { compareDocuments } from '../../core/comparison/index.js';
import { NormalizedDocumentSchema, type NormalizedDocument } from '../../schemas/index.js';
import type { CompareArgs } from '../args.js';
import type { CliDeps } from '../main.js';
import { compareEnvelope, errorEnvelope } from '../envelope.js';
import { ERROR_EXIT_CODES } from '../exit.js';

type Outcome = { exitCode: number; output: string };
type ReadResult = { ok: true; document: NormalizedDocument } | { ok: false; outcome: Outcome };

/** Reads and validates both inputs, then compares them. Never writes files. */
export async function runCompare(args: CompareArgs, deps: CliDeps): Promise<Outcome> {
  const base = await readReport(resolve(deps.cwd, args.baseReport), 'base');
  if (!base.ok) return base.outcome;
  const head = await readReport(resolve(deps.cwd, args.headReport), 'head');
  if (!head.ok) return head.outcome;

  const outcome = compareDocuments(base.document, head.document, { allowPartial: args.allowPartial });
  if (!outcome.ok) return refusal(outcome.error);
  return { exitCode: EXIT_CODES.OK, output: compareEnvelope(outcome.result) };
}

async function readReport(path: string, side: 'base' | 'head'): Promise<ReadResult> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return failed('usage_error', `${side} report cannot be read`, ERROR_EXIT_CODES.usage_error);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return failed('invalid_report', `${side} report is not valid JSON`, ERROR_EXIT_CODES.invalid_report);
  }

  const parsed = NormalizedDocumentSchema.safeParse(raw);
  if (!parsed.success) {
    return failed('invalid_report', `${side} report failed schema validation`, ERROR_EXIT_CODES.invalid_report);
  }
  return { ok: true, document: parsed.data };
}

function refusal(error: 'incompatible_reports' | 'partial_input_refused'): Outcome {
  if (error === 'incompatible_reports') {
    return {
      exitCode: ERROR_EXIT_CODES.incompatible_reports,
      output: errorEnvelope('incompatible_reports', 'reports come from different producers'),
    };
  }
  return {
    exitCode: ERROR_EXIT_CODES.partial_input_refused,
    output: errorEnvelope('partial_input_refused', 'a partial input was refused; pass --allow-partial to compare it'),
  };
}

function failed(code: 'usage_error' | 'invalid_report', message: string, exitCode: number): { ok: false; outcome: Outcome } {
  return { ok: false, outcome: { exitCode, output: errorEnvelope(code, message) } };
}
