# malformed-only

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: every result unusable (a missing `check_id`, and a `start` that is not an object). No usable entry remains, so the scan is failed.
Status: verify against real Semgrep.
