# out-of-scope

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic hosts only (`example.com` is the reserved example domain).
Covers: one in-scope alert, then a different port, a different scheme, a different host, and user info in the authority. The last four are excluded and counted in one `out_of_scope_target` diagnostic.
[verify] V3: field names and casing unverified against real ZAP.
