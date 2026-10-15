import { type ErrorCode, EXIT_CODES } from '../contracts/enums.js';

/** Spec 03 exit codes for every error envelope. */
export const ERROR_EXIT_CODES: Record<ErrorCode, number> = {
  usage_error: EXIT_CODES.USAGE_OR_CONFIG,
  invalid_configuration: EXIT_CODES.USAGE_OR_CONFIG,
  partial_input_refused: EXIT_CODES.PARTIAL,
  invalid_report: EXIT_CODES.INVALID_OR_INCOMPATIBLE_REPORT,
  incompatible_reports: EXIT_CODES.INVALID_OR_INCOMPATIBLE_REPORT,
};

/** `doctor`: 0 when every enabled tool is ready, else 2. */
export function doctorExitCode(ok: boolean): number {
  return ok ? EXIT_CODES.OK : EXIT_CODES.TOOL_UNAVAILABLE;
}
