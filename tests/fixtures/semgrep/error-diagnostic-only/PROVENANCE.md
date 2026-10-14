# error-diagnostic-only

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic messages only.
Covers: a `level: info` entry of an unlisted type and a `SemgrepWarning` without coverage impact. Both leave the scan complete.
Status: verify against real Semgrep. Spec 04 has no closed diagnostic code for these entries, so none is emitted (see the handoff report).
