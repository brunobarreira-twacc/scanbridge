# unknown-risk

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: risk text outside the `zap-1` table: `Critical`, lowercase `informational` (case-sensitive miss), empty string, and a missing `risk`. The missing and empty values are identical after reading, so they collapse to one candidate. `Medium` is the mapped control.
[verify] V3: the risk strings are unverified against real ZAP.
