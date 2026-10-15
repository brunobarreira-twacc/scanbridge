# duplicates

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: two identical alerts (collapsed to one candidate) and one alert that differs only in `messageId` (kept).
[verify] V3: field names and casing unverified against real ZAP.
