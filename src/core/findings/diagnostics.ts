import type { RawDiagnostic } from '../../contracts/adapter.js';
import { TEXT_FIELD_MAX } from '../../contracts/limits.js';
import type { Diagnostic } from '../../schemas/index.js';
import { textField } from './text.js';

const PRODUCERS: readonly string[] = ['semgrep', 'zap'];

/**
 * Builds schema diagnostics. `message` is Scanbridge-authored and passes through
 * unchanged. `detail` is producer text and becomes structured, untrusted text.
 * A `tool` outside the schema's producer enum is omitted.
 */
export function finalizeDiagnostics(raw: readonly RawDiagnostic[]): Diagnostic[] {
  return raw.map((diagnostic) => {
    const result: Diagnostic = { code: diagnostic.code, level: diagnostic.level, message: diagnostic.message };
    if (diagnostic.tool !== undefined && PRODUCERS.includes(diagnostic.tool)) {
      result.tool = diagnostic.tool as Diagnostic['tool'];
    }
    if (diagnostic.detail !== undefined) {
      result.detail = { ...textField(diagnostic.detail, TEXT_FIELD_MAX), untrusted: true };
    }
    return result;
  });
}
