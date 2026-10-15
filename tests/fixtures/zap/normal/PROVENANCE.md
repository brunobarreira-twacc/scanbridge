# normal

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only; no target content, no credentials.
Covers: one alert per mapped risk (Informational, Low, Medium), a query string, a non-empty `reference`, and every evidence field.
[verify] V3: field names, casing and risk strings are unverified against real ZAP.
