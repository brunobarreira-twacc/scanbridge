# findings

Producer version: unknown — verify against real SonarQube

Source: hand-written synthetic fixture in the shape of the SonarQube issues/search API (spec 05). Not captured from a real run.
Sanitization: none needed.
Covers: two issues — one VULNERABILITY (HIGH severity, textRange location) and one BUG (BLOCKER severity, line fallback location); projectKey prefix is stripped from component.
[verify] V3: field names and casing unverified against real SonarQube.
