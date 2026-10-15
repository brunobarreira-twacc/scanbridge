# numeric-strings

Producer version: unknown — verify against real ZAP

Source: hand-written synthetic fixture in the shape of the ZAP alerts API (spec 05). Not captured from a real run.
Sanitization: synthetic values only.
Covers: numeric-looking strings (`pluginId`, `confidence`, `param`, `messageId`) are kept verbatim as text. A `messageId` that is a JSON number is not text, so it gives `message_id` null.
[verify] V3: field names and casing unverified against real ZAP.
