import { inspect } from 'node:util';

const MASK = '[REDACTED]';

/** Wraps a secret (the ZAP API key). Every implicit conversion yields a mask; only `reveal()` returns the value. */
export class SensitiveString {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return MASK;
  }

  toJSON(): string {
    return MASK;
  }

  [inspect.custom](): string {
    return MASK;
  }
}
