import { hasProhibitedControl } from './identity.js';

export class UrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UrlError';
  }
}

export interface NormalizedUrl {
  /** Lowercase scheme and host, default port dropped. */
  origin: string;
  /** Normalized path, percent-encoding applied. */
  path: string;
  /** Sorted, deduplicated query parameter names. Values are never kept. */
  queryNames: string[];
  /** `origin` + `targetPath`. */
  url: string;
  /** `path`, plus `?name&name` when names exist. */
  targetPath: string;
}

const SCHEME_PREFIX = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/**
 * Normalizes an http or https URL for fingerprinting. Rejects user info,
 * fragments, control characters and backslashes. Dot segments are resolved by
 * the WHATWG parser. Only percent-encoded unreserved characters are decoded.
 * Remaining percent hex is uppercased. Query values are dropped.
 */
export function normalizeUrl(input: string): NormalizedUrl {
  const parsed = parseHttpUrl(input, { allowPath: true });
  const path = normalizePercentEncoding(parsed.pathname, 'path');
  const queryNames = queryParameterNames(parsed.search);
  const targetPath = queryNames.length > 0 ? `${path}?${queryNames.join('&')}` : path;
  return {
    origin: parsed.origin,
    path,
    queryNames,
    url: `${parsed.origin}${targetPath}`,
    targetPath,
  };
}

/** Accepts only a bare origin: scheme, host and optional port. */
export function normalizeOrigin(input: string): string {
  return parseHttpUrl(input, { allowPath: false }).origin;
}

function parseHttpUrl(input: string, options: { allowPath: boolean }): URL {
  if (hasProhibitedControl(input)) throw new UrlError('control character in URL');
  if (input !== input.trim()) throw new UrlError('surrounding whitespace in URL');
  if (input.includes('\\')) throw new UrlError('backslash in URL');
  if (input.includes('#')) throw new UrlError('fragment in URL');

  const prefix = SCHEME_PREFIX.exec(input);
  if (!prefix) throw new UrlError('URL must be absolute with an http or https scheme');
  const scheme = (prefix[1] ?? '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') throw new UrlError(`unsupported scheme: ${scheme}`);

  const rest = input.slice(prefix[0].length);
  const authority = rest.split(/[/?]/, 1)[0] ?? '';
  if (authority === '') throw new UrlError('missing host in URL');
  if (authority.includes('@')) throw new UrlError('user info in URL');
  if (!options.allowPath && rest.length > authority.length) {
    throw new UrlError('origin must not contain a path, query or fragment');
  }

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new UrlError('invalid URL');
  }
  if (parsed.username !== '' || parsed.password !== '') throw new UrlError('user info in URL');
  return parsed;
}

/** Rejects percent signs that do not start a two-digit hex escape. */
function normalizePercentEncoding(text: string, part: string): string {
  if (/%(?![0-9A-Fa-f]{2})/.test(text)) throw new UrlError(`invalid percent escape in ${part}`);
  return text.replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) => {
    const ch = String.fromCharCode(Number.parseInt(hex, 16));
    return UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
  });
}

function queryParameterNames(search: string): string[] {
  if (search.length <= 1) return [];
  const names = search
    .slice(1)
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      return normalizePercentEncoding(eq < 0 ? pair : pair.slice(0, eq), 'query');
    })
    .filter((name) => name !== '');
  return [...new Set(names)].sort();
}
