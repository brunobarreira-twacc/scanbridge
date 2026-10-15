import { open } from 'node:fs/promises';
import { RAW_JSON_MAX_BYTES } from '../../contracts/limits.js';
import { rawTooLarge } from './limits.js';

export type OfflineRead = { ok: true; bytes: Uint8Array } | { ok: false; reason: 'too_large' | 'unreadable' };

/** Reads the offline report into memory; never more than one byte past the cap. */
export async function readOfflineReport(path: string): Promise<OfflineRead> {
  let handle;
  try {
    handle = await open(path, 'r');
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) return { ok: false, reason: 'unreadable' };
    if (rawTooLarge(info.size)) return { ok: false, reason: 'too_large' };
    const buffer = Buffer.alloc(Math.min(info.size, RAW_JSON_MAX_BYTES) + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (rawTooLarge(length)) return { ok: false, reason: 'too_large' };
    return { ok: true, bytes: buffer.subarray(0, length) };
  } catch {
    return { ok: false, reason: 'unreadable' };
  } finally {
    await handle.close();
  }
}
