# error-coverage-loss

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic messages only.
Covers: every coverage-loss row of the spec 05 `errors[]` table, one per entry. The `Timeout` entry carries `level: info` to show that coverage takes precedence over level.
Status: verify against real Semgrep.
