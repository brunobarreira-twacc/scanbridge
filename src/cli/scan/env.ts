import type { Env } from '../../config/types.js';
import type { EnvReader } from '../../contracts/ports.js';

/** Config loading reads variables only by name through the injected reader; nothing is copied eagerly. */
export function envView(reader: EnvReader): Env {
  return new Proxy({} as Record<string, string | undefined>, {
    get: (_target, name) => (typeof name === 'string' ? reader.get(name) : undefined),
  });
}
