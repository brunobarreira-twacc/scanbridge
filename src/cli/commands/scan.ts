import { errorEnvelope } from '../envelope.js';
import { ERROR_EXIT_CODES } from '../exit.js';

/** Placeholder until T14 replaces it; every valid `scan` invocation lands here. */
export function runScan(): { exitCode: number; output: string } {
  return { exitCode: ERROR_EXIT_CODES.usage_error, output: errorEnvelope('usage_error', 'scan not implemented') };
}
