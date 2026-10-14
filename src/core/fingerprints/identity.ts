import {
  METHOD_MAX,
  PARAM_MAX,
  PATH_MAX,
  PRODUCER_REFERENCE_MAX,
  RULE_ID_MAX,
  URL_MAX,
} from '../../contracts/limits.js';
import { sha256Hex } from './hash.js';

export type IdentityKind = 'rule_id' | 'producer_reference' | 'path' | 'url' | 'method' | 'param';

export type IdentityDegradation = 'oversized' | 'invalid';

export interface GuardedIdentity {
  value: string;
  degraded: boolean;
  reason?: IdentityDegradation;
}

const LIMITS: Record<IdentityKind, number> = {
  rule_id: RULE_ID_MAX,
  producer_reference: PRODUCER_REFERENCE_MAX,
  path: PATH_MAX,
  url: URL_MAX,
  method: METHOD_MAX,
  param: PARAM_MAX,
};

/** True if the value has a code point below U+0020 or equal to U+007F. */
export function hasProhibitedControl(value: string): boolean {
  return /[\u0000-\u001F\u007F]/.test(value);
}

/**
 * Applies the identity-value rules from spec 04. Methods are uppercased first.
 * Control characters win over size. A failing value is replaced by a placeholder
 * built from the SHA-256 of the value, so equal inputs give equal placeholders.
 * Nothing is truncated or repaired.
 */
export function guardIdentity(value: string, kind: IdentityKind): GuardedIdentity {
  const candidate = kind === 'method' ? value.toUpperCase() : value;

  if (hasProhibitedControl(candidate)) {
    return { value: `[invalid:${sha256Hex(candidate)}]`, degraded: true, reason: 'invalid' };
  }

  if ([...candidate].length > LIMITS[kind]) {
    return { value: `[oversized:${sha256Hex(candidate)}]`, degraded: true, reason: 'oversized' };
  }

  return { value: candidate, degraded: false };
}
