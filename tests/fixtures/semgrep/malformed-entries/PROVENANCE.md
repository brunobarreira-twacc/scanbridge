# malformed-entries

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: entries missing `check_id`, `path` or `end`. Each is unusable and counted. One usable entry remains, so the scan is partial.
Status: verify against real Semgrep.
