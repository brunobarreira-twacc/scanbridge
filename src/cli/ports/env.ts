import type { EnvReader } from '../../contracts/ports.js';

export class ProcessEnv implements EnvReader {
  get(name: string): string | undefined {
    return process.env[name];
  }
}
