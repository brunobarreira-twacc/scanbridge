# Scanbridge specifications

Phase: **approved for implementation**. No code, project scaffolding or dependencies exist yet. All specifications are approved.

No design decisions are open. Items V1, V2 and V4 are verified on Semgrep 1.180.0; V5 is verified for Semgrep's local-rule MVP path. The remaining items are implementation-time checks against real tool versions and do not block implementation.

Source: `pprompts/scanbridge_initial_prompt.md`; decisions were resolved in a design interview (Q1–Q37) and review rounds. Each contract is settled in its owning spec.

## Index and reading order

| # | File | Owns | Status |
|---|---|---|---|
| 1 | [00-product-context.md](00-product-context.md) | Problem, workflow, boundaries, glossary | approved |
| 2 | [01-scope-and-decisions.md](01-scope-and-decisions.md) | Scope, non-goals, runtime, security, limits, responsibilities | approved |
| 3 | [02-architecture.md](02-architecture.md) | Components, ports, pipeline, storage, redaction, serialization | approved |
| 4 | [03-cli-contract.md](03-cli-contract.md) | Commands, exit codes, envelopes, `tools.yaml` | approved |
| 5 | [04-finding-schema.md](04-finding-schema.md) | `normalized.json`, enums, fingerprints, identifier limits | approved |
| 6 | [05-tool-adapters.md](05-tool-adapters.md) | Adapter contract, Semgrep, ZAP, mappings | approved |
| 7 | [06-testing-and-acceptance.md](06-testing-and-acceptance.md) | Test layers, coverage, acceptance | approved |
| 8 | [07-comparison.md](07-comparison.md) | Authority, target comparability, `findings[]`, state precedence | approved |

Status values: `draft`, `approved`, `implemented`. Tags in specs: **[verify]** = pending verification.

## Settled decisions

Defined in the owning specs, not repeated here. Highlights: one JSON envelope on stdout per command; exit codes 0–5; redact before fingerprint and persistence, failing closed; byte-reproducible `normalized.json` via a canonical serializer; versioned fingerprints and severity mappings; `unverified` completeness for offline imports; Semgrep local rule files are the only authoritative rule source; ZAP uses the alerts API only; file IO sits behind injected orchestration ports.

Former provisional defaults now settled:

| Item | Settled by | Owner |
|---|---|---|
| Comparison relevant fields, `severity_comparison`, state precedence (old P3) | Review round 3 | [07](07-comparison.md) |
| ZAP fingerprint path includes sorted query names, excludes origin (P4) | Q4, Q26, Q36 | [04](04-finding-schema.md) |
| Local rules are files, not directories (P6, part) | Q8 | [03](03-cli-contract.md) |
| ZAP deadline max 3600 s; env-var name pattern `^[A-Za-z_][A-Za-z0-9_]{0,63}$` (P7) | Q14; user correction | [01](01-scope-and-decisions.md), [02](02-architecture.md) |
| Count limits use `partial_coverage`; size and identifier limits use `resource_limit_exceeded` (P9) | Q33, Q36, review round 2 | [04](04-finding-schema.md) |
| Truncatable fields always use `{text, truncated, original_length}` (P11) | Q33 (stable field type) | [04](04-finding-schema.md) |
| Identifier limits and over-limit behavior (P12, part) | Review round 2 | [04](04-finding-schema.md) |
| ZAP comparisons can be authoritative with origin-only identity; asserted revisions never affect authority | Q17, review round 3 | [07](07-comparison.md) |

## Verified

| ID | Result | Owner |
|---|---|---|
| V1 | Semgrep 1.180.0 exit 7 emits parseable JSON with empty `results` and `paths.scanned`. Scanbridge returns failed/exit 3 and persists no raw or normalized report | [05](05-tool-adapters.md) |
| V2 | Nested list-encoded type `["PartialParsing", [{path,start,end}]]` on Semgrep 1.180.0: exit 0, file kept in `paths.scanned`, partial/exit 4 with findings preserved | [05](05-tool-adapters.md) |
| V4 | Plain Semgrep 1.180.0 suppresses `// nosemgrep`; `--disable-nosem` retains the finding | [05](05-tool-adapters.md) |

## Pending verification

Resolve with real tool output for the pinned versions.

| ID | Item | Owner |
|---|---|---|
| V3 | ZAP alerts-API field names, casing and risk/confidence strings (read from source, not live output) | [05](05-tool-adapters.md) |
| V5 | Supported Semgrep and ZAP versions to pin for fixtures. Semgrep 1.180.0 is verified for the local-rule MVP path; ZAP is still open | [06](06-testing-and-acceptance.md) |
| V6 | Whether files skipped by Semgrep's own timeout threshold appear in `paths.scanned`/`skipped` | [05](05-tool-adapters.md) |
| V7 | Resolved-rule digest for registry and `auto` modes. Q8 asked for one; until a verified way exists `rules_digest` is null (old P1). Those scans are non-authoritative regardless | [05](05-tool-adapters.md) |
| V8 | Sufficiency of the built-in value-redaction pattern set. A source-only synthetic Bearer token passed on Semgrep 1.180.0 (absent from every artifact, `redaction_summary.bearer` 1); this does not establish sufficiency | [02](02-architecture.md) |
| V9 | Limit values (text, identifier, size, count) against real fixtures | [01](01-scope-and-decisions.md), [04](04-finding-schema.md) |

## Known limitations

- ZAP cannot distinguish an externally stopped spider from a completed one.
- Value-pattern redaction is best-effort; persisted source text may still contain credentials. Consumers must treat everything as sensitive and untrusted.
- Fingerprints can change with formatting, refactoring or producer-version changes.
- The allowed-origin list is a safety guard, not a security boundary.
- ZAP `rules_digest` is null; request/response bodies and source mapping are absent.
- Registry and `auto` Semgrep rules are not pinned.
- Offline ZAP imports can be compared but never authoritatively.
- An authoritative ZAP comparison does not prove the app under test matched any asserted revision; the caller owns that.
