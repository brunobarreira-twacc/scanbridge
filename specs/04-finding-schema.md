# 04 — Finding schema, fingerprints, limits

Status: approved. Owns: `normalized.json` shape, closed enums, text fields, fingerprints, severity, identifier limits. Comparison semantics: [07](07-comparison.md).

Zod is the source of truth for validation and field shape (`z.toJSONSchema()` emitted to committed `schemas/`). Zod does not guarantee JSON key order; stable bytes come from the canonical serializer in [02](02-architecture.md). `schema_version` is `"1"`. Enums below are closed per schema version; changing them is a version change. All producer-originated strings are untrusted data ([00](00-product-context.md)).

## `normalized.json`

Deterministic evidence only ([02](02-architecture.md) for serialization).

| Field | Notes |
|---|---|
| `schema_version`, `content_trust` | `content_trust` is always `"untrusted_producer_content"` |
| `producer`, `producer_version` | `producer_version` is null if unknown; caller-asserted for offline |
| `target` | `{kind:"git", relative_path, revision, dirty, content_digest}` · `{kind:"directory", relative_path, content_digest}` · `{kind:"http_origin", origin, asserted_revision?}`. `content_digest` may be null. Comparability: [07](07-comparison.md) |
| `completeness`, `authoritative`, `non_authoritative_reasons[]` | see enums |
| `fingerprint_version`, `severity_mapping_version`, `redaction_policy_version` | e.g. `v1`, `semgrep-1`, `zap-1` |
| `rules_digest` | Semgrep: digest of local rule files; `null` for ZAP, registry and auto |
| `configuration_digest` | see [03](03-cli-contract.md) |
| `raw_sha256_before_redaction`, `raw_sha256_after_redaction`, `redaction_summary` | counts by rule id, never values |
| `findings[]` | sorted by fingerprint |

Not present: `scan_id`, timestamps, durations, paths, operational diagnostics (they live in `scan-result.json`).

Target digest: SHA-256 over records of `(relative path, entry type, executable bit, content SHA-256)`, sorted by normalized path and encoded unambiguously (canonical JSON array). Git targets enumerate tracked plus untracked-not-ignored files under the target; others walk the directory. Symlinks are hashed by link text, never followed. `.git` and the output base directory are excluded ([03](03-cli-contract.md)).

## Finding

| Field | Notes |
|---|---|
| `fingerprint`, `fingerprint_quality` | `exact` or `degraded` |
| `producer_fingerprint` | producer's own value if present; never used for identity |
| `rule_id` | Semgrep `check_id`; ZAP plugin ID. Fingerprint input |
| `producer_reference` | ZAP `alertRef` after sanitization, never derived from `rule_id` or the fingerprint; null for Semgrep and when ZAP omits it. Fingerprint input |
| `title`, `description` | text fields |
| `severity`, `severity_original`, `severity_complete` | group severity; see Severity. Original preserved verbatim after sanitization |
| `confidence` | only when supplied by the producer, verbatim text; else null. Never affects severity or comparison |
| `category`, `references[]` | null/empty when unsupplied |
| `status` | always `"open"` in the MVP (comparison states live in compare output) |
| `redactions_applied` | true if any associated value was replaced or removed |
| `occurrence_count`, `occurrences[]` | same fingerprint in one scan is grouped, never ordinal-suffixed |

Occurrence: its own `severity` and `severity_original`, optional `source_location {path, start_line, start_col, end_line, end_col}` (Semgrep), optional `runtime_location {url, method, param}` (ZAP), and `evidence`. ZAP never gets `source_location`; `source_location.inferred` is reserved and produced by no MVP component.

Text field (anything truncatable: title, description, snippet, evidence, detail): `{"text":"…","truncated":false,"original_length":123}`. `original_length` is a code-point count only. Limits are in [01](01-scope-and-decisions.md); truncation happens after redaction, never inside a code point.

Descriptive untrusted text (title, description, evidence, snippets, `severity_original`, `confidence`, references, diagnostic `detail`) has these control characters replaced by U+FFFD: U+0000–U+0008, U+000B, U+000C, U+000E–U+001F, U+007F. Tab, LF and CR are preserved until field-specific canonicalization. Identity values follow the rule in the limits section instead.

## Severity

`info | low | medium | high | critical | unknown`. Ranks `info=0 … critical=4`; `unknown` has no rank. Mapping tables: [05](05-tool-adapters.md).

Occurrences with different original severities are grouped under one fingerprint, and each keeps its own `severity` and `severity_original`. The finding's `severity` is the highest-ranked known occurrence severity; its `severity_original` is that of the first occurrence, in canonical order, that has this severity. If any occurrence is unknown, `severity_complete` is false (severity comparison becomes incomparable); if all are unknown, `severity` is `unknown` and `severity_original` comes from the first occurrence in canonical order.

## Fingerprints

```text
fingerprint = "v1:" + lowercaseHex(sha256(utf8("v1:" + canonicalJson(material))))
```

`canonicalJson` is RFC 8785 over a JSON array. Strings are NFC.

| Producer | `material` |
|---|---|
| semgrep (exact) | `["semgrep", rule_id, repository-root-relative POSIX path, canonical_snippet]` |
| semgrep (degraded) | `["semgrep", rule_id, path, start_line, start_col, end_line, end_col]` |
| zap | `["zap", rule_id, producer_reference or "", METHOD, target_path, param_name]` (`rule_id` = plugin ID, `producer_reference` = `alertRef`) |

- Redaction runs first. Canonical snippet = the full reported line range, obtained through the orchestration `SourceReader` ([02](02-architecture.md)), redacted, BOM removed, UTF-8 decoded, NFC, line endings to LF, every whitespace run collapsed to one space, trimmed. `extra.lines` and the producer's fingerprint never feed identity.
- Unreadable source (outside target, symlink, over 1 MiB, invalid UTF-8, changed) gives `degraded`, reason `fingerprint_degraded`, same-named diagnostic. Invalid UTF-8 is never repaired with U+FFFD.
- ZAP `target_path` = normalized path plus sorted, deduplicated query parameter names (`/a?x&y`); the origin and all query values are excluded. Attack payloads and response data are excluded.
- ZAP URL normalization: lowercase scheme and host, drop default port, reject user info and fragments, resolve dot segments, decode only percent-encoded unreserved characters, uppercase remaining percent hex, keep a meaningful trailing slash.
- Changing the algorithm or canonicalization changes `fingerprint_version`.

## Identifier and location limits

Identity values (`rule_id`, `producer_reference`, paths, URLs, HTTP methods, parameter names) are untrusted and never silently altered: they are redacted, then checked for control characters (any code point below U+0020, or U+007F) and measured in code points. HTTP methods are uppercased first. Text-field limits are in [01](01-scope-and-decisions.md).

| Value | Limit | In fingerprint |
|---|---|---|
| `rule_id` | 256 | yes |
| `producer_reference` (`alertRef`) | 128 | yes |
| Repository-relative path | 1,024 | yes (Semgrep) |
| Normalized URL | 2,048 | yes, as `target_path` (ZAP) |
| HTTP method | 16 | yes (ZAP) |
| Parameter name | 256 | yes (ZAP) |
| Each external reference | 2,048 | no |
| External references per finding | 20 | no |

Over-limit behavior (never silent truncation of fingerprint inputs):

- **Fingerprint-bearing value:** the finding is kept. The stored value and the fingerprint material both use the placeholder `[oversized:<sha256 hex of the sanitized, redacted original>]`, which is deterministic across scans and collision-resistant. `fingerprint_quality` is `degraded`, reason `fingerprint_degraded`, plus a `resource_limit_exceeded` warning diagnostic. An over-limit Semgrep path also skips the source read, so the location-based degraded material is used with the placeholder path. An over-limit URL makes both `url` and `target_path` placeholders.
- **Control characters in an identity value:** never replaced, because replacement could collide identities. The finding is kept; the stored value and the material use `[invalid:<sha256 hex of the redacted original>]`; `fingerprint_quality` is `degraded`, reason `fingerprint_degraded`, plus a `malformed_report` warning diagnostic.
- **External reference:** an over-length reference is omitted, never truncated; beyond 20 references the first 20 in sorted order are kept. A `resource_limit_exceeded` warning records the counts. Completeness is unchanged.
- **Unusable entry:** required identity values missing or not strings (Semgrep: `check_id`, `path`, `start`/`end`; ZAP: `pluginId`, `url`) exclude the entry and add a `malformed_report` diagnostic with the count. The scan is `partial` if usable entries remain and `failed` (exit 3) if none do.
- **ZAP `alertRef` missing, empty or not a string:** `producer_reference` is null, the material uses `""`, quality is `degraded`, reason `fingerprint_degraded`. Any other string, including `unknown`, is an ordinary value.

## Diagnostics and reasons

Diagnostic `{code, level: info|warn|error, tool?, message, detail?}`. `message` is Scanbridge-authored only; producer text goes in `detail` (redacted, control characters sanitized, truncated, `untrusted: true`).

Diagnostic codes (closed): `tool_unavailable`, `tool_execution_failed`, `tool_timeout`, `partial_coverage`, `resource_limit_exceeded`, `unmapped_error_type`, `unmapped_severity`, `non_deterministic_rules`, `out_of_scope_target`, `redaction_failed`, `malformed_report`, `target_identity_unavailable`, `target_changed_during_scan`, `fingerprint_degraded`, `no_files_scanned`, `no_urls_discovered`, `zap_session_not_clean`, `zap_unreachable_or_rejected`, `bad_api_key`, `target_url_overridden`.

`tool_unavailable` = not found or failed its probe; `tool_execution_failed` = ran and failed. `resource_limit_exceeded` = raw or normalized size failure, or an identifier/reference limit above; finding/occurrence count limits keep the first canonical entries and add `partial_coverage`.

Completeness: `complete` (live coverage verified), `partial` (concrete coverage loss observed), `unverified` (imported, cannot prove collection). Failed scans have no `normalized.json`.

Scan-level non-authoritative reasons (closed): `partial_scan`, `registry_rules`, `auto_rules`, `fingerprint_degraded`, `unmapped_severity`, `offline_report`.
Compare-level (applied by [07](07-comparison.md)): `partial_input_allowed`, `fingerprint_version_mismatch`, `severity_mapping_version_mismatch`, `redaction_policy_mismatch`, `rules_mismatch`, `producer_version_mismatch`, `producer_version_incomparable`, `target_identity_incomparable`, `base_input_non_authoritative`, `head_input_non_authoritative`.

## Examples (synthetic)

Semgrep:

```json
{"fingerprint":"v1:<64 hex>","fingerprint_quality":"exact","rule_id":"rules.sql-injection","producer_reference":null,
 "title":{"text":"rules.sql-injection","truncated":false,"original_length":19},
 "description":{"text":"User input reaches a SQL query.","truncated":false,"original_length":31},
 "severity":"high","severity_original":"ERROR","severity_complete":true,"confidence":null,"category":null,
 "references":[],"status":"open","redactions_applied":false,"occurrence_count":1,
 "occurrences":[{"severity":"high","severity_original":"ERROR",
   "source_location":{"path":"src/db.ts","start_line":42,"start_col":3,"end_line":42,"end_col":58},
   "evidence":{"snippet":{"text":"db.query(\"SELECT * FROM t WHERE id=\" + id)","truncated":false,"original_length":42}}}]}
```

ZAP:

```json
{"fingerprint":"v1:<64 hex>","fingerprint_quality":"exact","rule_id":"10202","producer_reference":"10202",
 "title":{"text":"Absence of Anti-CSRF Tokens","truncated":false,"original_length":27},
 "severity":"medium","severity_original":"Medium","severity_complete":true,
 "confidence":{"text":"Low","truncated":false,"original_length":3},"status":"open","occurrence_count":1,
 "occurrences":[{"severity":"medium","severity_original":"Medium",
   "runtime_location":{"url":"http://127.0.0.1:8080/login","method":"POST","param":""},
   "evidence":{"attack":null,"evidence":{"text":"<form action=\"/login\">","truncated":false,"original_length":22},"message_id":"17"}}]}
```
