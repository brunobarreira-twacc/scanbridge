# control-chars

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only. Control characters are written as JSON escapes.
Covers: a URL with U+0001, a URL with a tab, and a URL that does not parse. None can be origin-checked, so all three are excluded and counted in one `out_of_scope_target` diagnostic. The last alert is the in-scope control.
[verify] V3: field names and casing unverified against real ZAP.
