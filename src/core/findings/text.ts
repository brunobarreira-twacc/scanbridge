import type { TextField } from '../../schemas/index.js';

// U+0009 (tab), U+000A (LF) and U+000D (CR) are not in this set: they survive until field-specific canonicalization.
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/** Replaces descriptive-text control characters with U+FFFD (spec 04). One code point in, one out. */
export function sanitizeText(value: string): string {
  return value.replace(CONTROL_CHARACTERS, '�');
}

/** Sanitized plain string: no truncation, no structure. */
export function plainText(value: string): string {
  return sanitizeText(value);
}

/** Sanitized, then truncated by code points (never inside one). `original_length` counts code points before truncation. */
export function textField(value: string, limit: number): TextField {
  const codePoints = [...sanitizeText(value)];
  const truncated = codePoints.length > limit;
  return {
    text: truncated ? codePoints.slice(0, limit).join('') : codePoints.join(''),
    truncated,
    original_length: codePoints.length,
  };
}
