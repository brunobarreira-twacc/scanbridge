# alertref-missing

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: `alertRef` absent, and `alertRef` present but empty. Both give `producer_reference` null.
[verify] V3: field names and casing unverified against real ZAP.
