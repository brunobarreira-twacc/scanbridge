# traditional-report

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of a ZAP Traditional JSON report. Not captured from a real run.
Sanitization: synthetic values only.
Covers: the Traditional JSON report shape, which is unsupported. `parse` must reject it with `unsupported_shape`.
[verify] V3: the Traditional report field names are unverified against real ZAP.
