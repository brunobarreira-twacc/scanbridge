# exclusions-not-partial

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: an intentional `.gitignore` exclusion listed under `paths.skipped`. It never makes the scan partial. Whether timeout-threshold skips appear in `paths.scanned` or `paths.skipped` is unknown: [verify] V6. The adapter relies on `errors[]` only.
Status: verify against real Semgrep.
