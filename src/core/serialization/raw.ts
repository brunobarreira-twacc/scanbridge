import { sha256Hex } from '../fingerprints/hash.js';

/**
 * Redacted raw artifact text: parsed key and array order is kept (never sorted), 2-space indent,
 * LF, one trailing newline. JS objects cannot hold array-index-like keys in insertion order, so
 * those keys come out in engine order; producer raw files are not expected to rely on them.
 */
export function serializeRaw(parsed: unknown): string {
  assertJsonValue(parsed, '$');
  return `${JSON.stringify(parsed, null, 2)}\n`;
}

/** Lowercase SHA-256 of the exact UTF-8 bytes of `text`. */
export function sha256Utf8(text: string): string {
  return sha256Hex(new TextEncoder().encode(text));
}

function assertJsonValue(value: unknown, path: string): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${path}: non-finite number`);
    return;
  }
  if (Array.isArray(value)) {
    // Index loop: holes and undefined entries must fail, not become `null`.
    for (let i = 0; i < value.length; i++) assertJsonValue(value[i], `${path}[${i}]`);
    return;
  }
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) assertJsonValue(child, `${path}.${key}`);
    return;
  }
  throw new TypeError(`${path}: not a JSON value (${typeof value})`);
}
