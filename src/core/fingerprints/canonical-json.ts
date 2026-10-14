// RFC 8785 (JCS) for the value shapes fingerprint material uses: strings, integers,
// booleans, null, arrays and objects. Floats and non-finite numbers are rejected.

export type CanonicalJson =
  | string
  | number
  | boolean
  | null
  | readonly CanonicalJson[]
  | { readonly [key: string]: CanonicalJson };

/**
 * Serializes `value` as RFC 8785 canonical JSON. String escaping is the ES
 * `JSON.stringify` form that RFC 8785 mandates; object members are sorted by
 * UTF-16 code units.
 */
export function canonicalJson(value: CanonicalJson): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isInteger(value)) {
        throw new TypeError(`canonicalJson: only integers are allowed, got ${String(value)}`);
      }
      return String(value);
    case 'object':
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
      }
      const record = value as { readonly [key: string]: CanonicalJson };
      return `{${Object.keys(record)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key] as CanonicalJson)}`)
        .join(',')}}`;
    default:
      throw new TypeError(`canonicalJson: unsupported value of type ${typeof value}`);
  }
}
