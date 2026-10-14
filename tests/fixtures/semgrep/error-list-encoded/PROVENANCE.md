# error-list-encoded

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic messages only.
Covers: list-encoded `type` values such as `["PartialParsing", …]`. The strongest element classifies the entry. The wire format is unverified: [verify] V2. The classification follows the documented table but is not confirmed against real output.
Status: verify against real Semgrep.
