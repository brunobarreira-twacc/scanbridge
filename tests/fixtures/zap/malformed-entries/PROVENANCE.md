# malformed-entries

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: six unusable entries (no `pluginId`, no `url`, a numeric `pluginId`, an array `url`, a bare string, and `null`) and one usable entry. The unusable entries are counted in `unusableCount`.
Note: the expected completeness is `complete`, which follows the T11 completeness rule. Spec 04 says unusable entries make a scan `partial` (or `failed` when none are usable). That conflict is reported in the T11 handoff and is unresolved.
[verify] V3: field names and casing unverified against real ZAP.
