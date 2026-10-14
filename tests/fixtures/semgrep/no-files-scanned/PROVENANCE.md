# no-files-scanned

Producer version: unknown — verify against real Semgrep

Source: hand-written synthetic fixture in the shape of `semgrep scan --json` (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: an empty `paths.scanned` with a result present. Gives partial with `no_files_scanned`, even though no error was reported.
Status: verify against real Semgrep.
