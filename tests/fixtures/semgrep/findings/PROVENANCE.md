# findings

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: the secret-like value and its source line are already redacted placeholders (`[REDACTED]`); no real credentials.
Covers: every mapped `semgrep-1` severity, one unknown severity (`BLOCKER`), `metavars` (must never reach a candidate), `lines` (kept as evidence), `metadata` with expected types, a fingerprint, a redacted source, an unreadable source (`too_large`), and a redaction pointer for result index 1.
Status: verify against real Semgrep.
