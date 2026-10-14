import { createHash } from 'node:crypto';

/** Lowercase hex SHA-256. Strings are hashed as UTF-8. */
export function sha256Hex(input: Uint8Array | string): string {
  return createHash('sha256').update(input).digest('hex');
}
