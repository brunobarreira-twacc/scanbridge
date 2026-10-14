# 07 — Comparison

Status: approved. Owns: authority rules for `compare`, target comparability, `findings[]` entries, state precedence, absence-based claims.

CLI flags, exit codes and refusals (`partial_input_refused`, `invalid_report`, `incompatible_reports`) are in [03](03-cli-contract.md). Enums and field shapes are in [04](04-finding-schema.md).

## Authority

Comparison `authoritative` is true only when both inputs are authoritative, no compare-level reason applies, and `--allow-partial` was not needed. Reasons (closed list in [04](04-finding-schema.md)):

- Each input's own reasons are kept separately; a non-authoritative input adds `base_input_non_authoritative` / `head_input_non_authoritative`; an allowed partial input adds `partial_input_allowed`.
- `producer_version`: exact equality; unequal gives `producer_version_mismatch`; null on either side gives `producer_version_incomparable`.
- `rules_digest`, `redaction_policy_version`, `fingerprint_version`, `severity_mapping_version`: exact equality, else the matching `*_mismatch` reason.
- Target comparability (below).
- `configuration_digest` differences are reported as metadata only.

## Target comparability

| Kind | Subject (must match) | Identity evidence | Comparable when |
|---|---|---|---|
| `git` | `relative_path` | `content_digest` | same kind and `relative_path`; both digests non-null |
| `directory` | `relative_path` | `content_digest` | same kind and `relative_path`; both digests non-null |
| `http_origin` | normalized `origin` | the origin itself | same kind and `origin` |

- Git `revision` and `dirty` are informational; before and after revisions are expected to differ.
- Failure adds `target_identity_incomparable`. A subject mismatch (kind, path or origin) also makes absence-based claims incomparable; a null digest alone adds only the reason.
- **ZAP decision:** caller-asserted `asserted_revision` is never identity evidence, is not required, is not verified, and never changes authority. Two `complete` live ZAP inputs with the same origin and otherwise compatible fields can be authoritative even when both carry asserted revisions. Authority does not claim the app under test matches any revision; the caller owns that. Offline (`unverified`) inputs are never authoritative. The output echoes each `asserted_revision` marked `asserted: true`.

## `findings[]`

Sorted by fingerprint, base entries before head entries. Each entry:

```json
{"fingerprint":"v1:<64 hex>","state":"changed","severity_comparison":"comparable",
 "changed_fields":["confidence"],"base":{"…":"reference"},"head":{"…":"reference"}}
```

| Field | Notes |
|---|---|
| `state` | `new`, `resolved`, `unchanged`, `changed`, `severity_increased`, `severity_decreased`, `incomparable` |
| `severity_comparison` | `comparable` or `incomparable` |
| `changed_fields` | Sorted names; empty for one-sided entries |
| `base`, `head` | Finding reference, or `null` when the side lacks the finding |

Finding reference: `rule_id`, `producer_reference`, `title`, `fingerprint_quality`, `severity`, `severity_original`, `severity_complete`, `confidence`, `occurrence_count`, `occurrence_severities`. Occurrences and evidence are not repeated; consumers read them from the input files by fingerprint.

Representation:

- Both sides: `base` and `head` set.
- Head-only: `base: null` (state `new`, or `incomparable`). Base-only: `head: null` (state `resolved`, or `incomparable`).
- One-sided entries always have `severity_comparison: "incomparable"` and `changed_fields: []`.
- Different `fingerprint_version`: no matching is attempted. Every finding of both inputs appears as its own one-sided entry with state `incomparable`.

## State precedence

First match wins:

1. `fingerprint_version` differs: `incomparable` for every entry.
2. One-sided finding: `incomparable` if absence is untrusted (below), else `new` (head only) or `resolved` (base only).
3. Both sides: `severity_increased` / `severity_decreased` if `severity_comparison` is `comparable` and ranks differ; else `changed` if `changed_fields` is non-empty; else `unchanged`.

A `severity_increased` or `severity_decreased` entry still lists any other `changed_fields`.

## Absence-based claims

A one-sided entry is `incomparable` when any of these holds:

- the input lacking the finding is `partial` or `unverified`;
- `rules_digest` differs (`rules_mismatch`);
- `redaction_policy_version` differs (fingerprint material derives from redacted text);
- target subject mismatch;
- either input carries scan-level reason `fingerprint_degraded`.

These do not affect absence: producer-version reasons, `severity_mapping_version_mismatch`, a null digest alone, `unmapped_severity`, `partial_input_allowed`.

## Severity comparison and changed fields

- `severity_comparison` is `comparable` only if both severities are known, both `severity_complete` are true and `severity_mapping_version` is equal. Ranks: `info=0 … critical=4`.
- `changed_fields` draws from `confidence`, `evidence`, `occurrence_count`, `occurrence_severities`, `severity_original`, `title`.
  - `evidence`: sorted per-occurrence evidence texts; locations and line numbers are excluded.
  - `occurrence_severities`: sorted multiset of occurrence `severity_original` values.
- Not compared: `description`, `references`, `category`, `producer_fingerprint`, `redactions_applied`, `fingerprint_quality`.

`summary` holds one count per state plus `severity_comparison_incomparable`.
