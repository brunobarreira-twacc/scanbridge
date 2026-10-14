import type { Target } from '../../schemas/index.js';

export interface TargetComparison {
  /** Kind, and path or origin, match. Absence-based claims require this. */
  subjectMatches: boolean;
  /** Identity evidence is present and matches. False adds `target_identity_incomparable`. */
  comparable: boolean;
}

/** Target comparability matrix from spec 07. Revisions are never identity evidence. */
export function compareTargets(base: Target, head: Target): TargetComparison {
  if (base.kind === 'http_origin' && head.kind === 'http_origin') {
    const sameOrigin = base.origin === head.origin;
    return { subjectMatches: sameOrigin, comparable: sameOrigin };
  }

  if (base.kind !== 'http_origin' && head.kind === base.kind && base.relative_path === head.relative_path) {
    const digestsPresent = base.content_digest !== null && head.content_digest !== null;
    return { subjectMatches: true, comparable: digestsPresent };
  }

  return { subjectMatches: false, comparable: false };
}
