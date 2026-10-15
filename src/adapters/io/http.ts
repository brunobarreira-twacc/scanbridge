import type { HttpClient, HttpResult } from '../../contracts/ports.js';
import type { SensitiveString } from '../../contracts/sensitive.js';

const CLOSED_CODES = new Set(['UND_ERR_SOCKET', 'UND_ERR_CLOSED', 'ECONNRESET', 'EPIPE']);
const SAFE_CODE = /^[A-Z0-9_]{1,64}$/;

/**
 * GET only, redirects not followed. `.reveal()` is called here and nowhere else.
 * Errors carry a code, never a message, URL or header value.
 */
export class FetchHttpClient implements HttpClient {
  async request(r: {
    url: string;
    headers: Record<string, string>;
    sensitiveHeaders?: Record<string, SensitiveString>;
    timeoutMs: number;
    maxBytes: number;
  }): Promise<HttpResult> {
    const signal = AbortSignal.timeout(r.timeoutMs);
    let response: Response;
    try {
      const headers = new Headers(r.headers);
      for (const [name, value] of Object.entries(r.sensitiveHeaders ?? {})) headers.set(name, value.reveal());
      response = await fetch(r.url, { method: 'GET', headers, redirect: 'manual', signal });
    } catch (err) {
      return signal.aborted ? { kind: 'timeout' } : failure(err);
    }

    const chunks: Uint8Array[] = [];
    let total = 0;
    let truncated = false;
    if (response.body) {
      const reader = response.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          const room = r.maxBytes - total;
          if (value.byteLength > room) {
            chunks.push(value.subarray(0, room));
            total += room;
            truncated = true;
            break;
          }
          chunks.push(value);
          total += value.byteLength;
        }
      } catch (err) {
        return signal.aborted ? { kind: 'timeout' } : { kind: 'error', code: errorCode(err) };
      }
      if (truncated) await reader.cancel().catch(() => undefined);
    }

    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { kind: 'response', status: response.status, body, truncated };
  }
}

function failure(err: unknown): HttpResult {
  const code = errorCode(err);
  return CLOSED_CODES.has(code) ? { kind: 'closed' } : { kind: 'error', code };
}

/** The undici or system code from the cause, never the message. */
function errorCode(err: unknown): string {
  const cause = (err as { cause?: { code?: unknown } } | undefined)?.cause;
  const own = (err as { code?: unknown } | undefined)?.code;
  for (const candidate of [cause?.code, own]) {
    if (typeof candidate === 'string' && SAFE_CODE.test(candidate)) return candidate;
  }
  return 'UNKNOWN';
}
