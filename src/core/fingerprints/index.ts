export { canonicalJson, type CanonicalJson } from './canonical-json.js';
export { sha256Hex } from './hash.js';
export {
  canonicalizeSnippet,
  fingerprintFromMaterial,
  semgrepDegraded,
  semgrepExact,
  sonarqube,
  sonarqubeDegraded,
  zap,
  type FingerprintMaterial,
} from './fingerprint.js';
export { normalizeOrigin, normalizeUrl, UrlError, type NormalizedUrl } from './url.js';
export {
  guardIdentity,
  hasProhibitedControl,
  type GuardedIdentity,
  type IdentityDegradation,
  type IdentityKind,
} from './identity.js';
export {
  compareOccurrences,
  type OccurrenceOrderInput,
  type RuntimeLocationKey,
  type SourceLocationKey,
} from './occurrences.js';
