# T04 — Fingerprints and identity primitives

Model: Haiku
Status: blocked
Depends on: T01
Parallel group: G1 (with T02, T03, T10)
Branch: ticket/T04-fingerprints

## Goal

Pure primitives for canonical JSON, fingerprints, URL normalization, identity-value guards and occurrence ordering.

## Read first

- `specs/04-finding-schema.md`: Fingerprints, Identifier and location limits, Severity (canonical order)
- `specs/02-architecture.md`: Deterministic serialization (last bullets)

## Owns

`src/core/fingerprints/**`, `tests/unit/fingerprints/**`.

## Requirements

- `canonicalJson(value)`: RFC 8785 for strings, integers, booleans, null, arrays, objects (members sorted by UTF-16 code units). Reject floats and non-finite numbers.
- `sha256Hex(bytes | string)`.
- `fingerprintFromMaterial(material: readonly (string | number)[]): string` = `"v1:" + sha256Hex(utf8("v1:" + canonicalJson(NFC-normalized material)))`.
- Material builders: `semgrepExact(ruleId, path, canonicalSnippet)`, `semgrepDegraded(ruleId, path, sl, sc, el, ec)`, `zap(ruleId, producerReference | "", METHOD, targetPath, param)` matching the spec 04 table (leading producer string included).
- `canonicalizeSnippet(text)`: strip BOM, NFC, CRLF and CR to LF, collapse every whitespace run to one space, trim. Input is already redacted by the caller.
- `normalizeUrl(input: string)`: returns `{ origin, path, queryNames, url, targetPath }` or throws `UrlError`. Rules: http/https only; reject user info and fragments; lowercase scheme and host; drop default port; resolve dot segments; decode only percent-encoded unreserved characters; uppercase remaining percent hex; keep a meaningful trailing slash; remove query values; sort and deduplicate query names. `targetPath` = path plus `?name&name` when names exist. `normalizeOrigin(input)` accepts only a bare origin (no path, query, fragment, user info).
- `hasProhibitedControl(value)`: any code point below U+0020 or U+007F.
- `guardIdentity(value, kind)` where `kind` is `rule_id | producer_reference | path | url | method | param`: returns `{ value, degraded: boolean, reason?: 'oversized' | 'invalid' }`. Method is uppercased first. Control characters win over size: replace the value with `[invalid:<sha256 hex of the original>]`; over the limit (code points, from `src/contracts/limits.ts`): `[oversized:<sha256 hex of the original>]`; else unchanged. Never truncates or repairs.
- `compareOccurrences(a, b)`: canonical order. Source locations by (path, start_line, start_col, end_line, end_col); runtime by (url, method, param, attack, evidence, message_id) with code-point string comparison and `null` first. Define the minimal structural input type locally.

## Tests (same ticket)

- RFC 8785 string and key-order vectors; integer output; float rejection.
- Fixed fingerprint golden values for one Semgrep exact, one degraded, one ZAP case; stability when whitespace, line endings or line numbers change in the snippet; different snippets differ.
- URL normalization table (case, default ports, dot segments, percent decoding and hex case, query values removed, names sorted and deduplicated, trailing slash kept, rejected inputs).
- `guardIdentity`: one below, exactly at and one above each limit; control character in each kind; two different over-limit values give different placeholders; identical values give identical placeholders.
- `compareOccurrences` total order for both occurrence shapes.

## Done when

`npm run build && node --test dist/tests/unit/fingerprints` passes.

## Verification items

V9 (identifier limit values) stays `[verify]`: read limits only from `src/contracts/limits.ts`.

## Notes

Callers pass already redacted values. ZAP origin and query values never enter fingerprint material.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V9. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
