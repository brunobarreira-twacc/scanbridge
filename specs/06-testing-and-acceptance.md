# 06 — Testing and acceptance

Status: approved. Owns: test layers, fixtures, required coverage, acceptance criteria.

## Layers

| Layer | Scope | Rules |
|---|---|---|
| Unit | `core/` (fingerprint, redaction, comparison, serialization) | Pure; no mocks |
| Adapter | `parse`, `sourceRefs`, `normalize` from sanitized fixtures and fake `sources`; `probe`, `scan` with fake `Runner` / `HttpClient`; orchestration with a fake `SourceReader` | No real tools, no network; adapters and `core/` import no filesystem module |
| Contract | Built CLI as a subprocess in a temp directory | Asserts stdout, stderr, exit code, artifacts. Fake `semgrep` executable first on `PATH`; in-process `127.0.0.1` HTTP server fakes ZAP |
| Live integration | Real Semgrep / ZAP | Only with `SCANBRIDGE_LIVE_SEMGREP=1` / `SCANBRIDGE_LIVE_ZAP=1`; skipped by default; not in the default CI command |

Runner: `node:test`. Default automated tests need no Semgrep, ZAP or network.

## Fixtures

- `tests/fixtures/<tool>/<case>/` with raw input, expected normalized output and `PROVENANCE.md` (producer version, source command, sanitization notes, `verify against real <tool>` where applicable).
- Sanitized or synthetic only: no private code, no real credentials.

## Required coverage

- Configuration validation: strict keys, rule-mode exclusivity, env-var name and length rules, path escape and symlink rejection, origin and URL rules.
- Adapter probing, including Semgrep version leniency and ZAP loopback/key/closed-connection cases.
- Semgrep and ZAP parsing and normalization, including every row of the Semgrep error table and both severity mappings with unknown values.
- Schema validation: committed `schemas/` equal regenerated output; representative valid and invalid documents give the same verdict from Zod and from the emitted schema (validated with `ajv`).
- Redaction: every built-in header, key and value pattern; env-var values; `metavars` removal; fail-closed path.
- Fingerprints: stability across line moves and whitespace; degraded path; ZAP URL normalization; grouping into `occurrences[]`.
- Determinism: identical inputs give identical `normalized.json` bytes.
- Malformed, partial and oversized reports; each limit tested one below, exactly at and one above.
- `SourceReader` ([02](02-architecture.md)): range read, path outside target, symlink, size at/over 1 MiB, invalid UTF-8, missing file, each yielding the specified result or degraded fingerprint; pure modules never receive a filesystem handle.
- Comparison ([07](07-comparison.md)): every state; state precedence including `severity_increased` with other `changed_fields`; base-only and head-only entry shapes (`null` side); differing `fingerprint_version` (all entries `incomparable`, no matching); each absence-based trigger and each non-trigger; `severity_comparison` for unknown, `severity_complete: false` and mapping mismatch; every compare-level reason; `--allow-partial`; `unverified` inputs.
- Target comparability per kind: git, directory (same/different path, null digest), http_origin (same/different origin); two complete live ZAP inputs with asserted revisions can be authoritative, an offline input never is.
- Grouped severity: occurrences with different original severities stay grouped, each keeps its own severity, finding `severity_original` follows the specified tie-break, and a changed `occurrence_severities` multiset appears in `changed_fields`.
- Offline ZAP: target URL from flag, from env, both (flag wins, `target_url_overridden`), neither (exit 2); `--config` and `--target-revision` handling; failures write `scan-result.json` but no raw or normalized artifact.
- Target digest before/after (`target_changed_during_scan`).
- Output directory ([03](03-cli-contract.md)): non-directory rejected; equal to target rejected; descendant of target excluded from both the digest and the Semgrep argv by normalized target-relative path, without making the scan partial; sibling, ancestor and outside paths not excluded; symlinked output base resolved; artifacts from a previous run inside the target never appear as findings or change the digest (scan twice).
- Identifier and location limits ([04](04-finding-schema.md)): for each of `rule_id`, `alertRef`, path, URL, method, parameter name, each reference and reference count, one below, exactly at and one above the limit; redaction applied before control-character validation and measurement, and identity values never repaired or altered; over-limit fingerprint inputs are never truncated (placeholder is deterministic and two different over-limit values do not collide); unusable entries give partial or failed.
- ZAP `alertRef`: present, missing, empty, non-string and over-limit cases; `producer_reference` is preserved, never derived from the plugin ID or fingerprint, and fingerprint quality is as specified.
- Canonical serialization ([02](02-architecture.md)): objects built with different key insertion orders and arrays in different input orders produce identical `normalized.json` bytes; each declared field-order list covers exactly the Zod keys; LF only and exactly one trailing newline; the dependency list stays `yaml` and `zod`. Raw artifacts: producer object-key and array order preserved (an unsorted fixture stays unsorted, and sorting rules never touch it), two-space indentation, UTF-8, LF, one trailing newline, and `raw_sha256_after_redaction` equals the SHA-256 of the exact persisted bytes. Dirty ZAP session: exit 3 with no raw and no `normalized.json`, `scan-result.json` written, identical envelope on stdout.
- Sanitization ([04](04-finding-schema.md)): each listed control character in descriptive text becomes U+FFFD while tab, LF and CR are preserved; control characters in identity values (id, reference, path, URL, method, parameter) are never repaired or silently altered; redaction runs first, then a value containing prohibited control characters uses the deterministic `[invalid:<sha256>]` placeholder, the finding gets `fingerprint_quality: degraded`, reason `fingerprint_degraded` and a `malformed_report` warning, and values differing only by control characters do not collide; invalid UTF-8 source stays degraded and is never repaired.
- ZAP environment rule ([03](03-cli-contract.md)): missing or invalid env-derived API URL, API key or target URL exits 2; the same invalid target value from a flag or static config exits 1; offline mode skips only API URL, key and session checks.
- Live ZAP pre-redaction hash: assembled document keeps page order and duplicates, identical pages give an identical hash, and deduplication and sorting occur only in normalization.
- Paths and output: Semgrep paths are repository-root-relative even when `--target` is a subdirectory; a missing `--output` base is created with symlink and path-safety checks; an existing `<scan_id>` directory is never overwritten.
- ZAP flow: dirty session, reset mode, scope regex, out-of-scope alerts, count change while paging, spider/passive deadlines, zero URLs, offline import.
- CLI contract for every command: stdout is exactly one JSON document plus newline; stderr holds logs only; exit codes per [03](03-cli-contract.md); exclusive directory creation; no empty reports.

## Secret canary

A synthetic, test-only secret appears in fake producer input, including a snippet for each built-in value pattern. It must not appear in raw or normalized artifacts, stdout, stderr, diagnostics, errors, thrown messages or snapshots. Configured env-var values are covered the same way.

## Acceptance — specification phase

- All files in `specs/` exist, are linked from the README and stay within roughly 40–170 lines each.
- Each contract has one owning file; others link to it.
- Settled decisions, pending verification and known limitations are separated in the README; any open decision is listed there, and the README never claims the design is closed while one remains.
- No code, `package.json`, CI or scaffolding exists.
- A human approves the specs before implementation starts.

## Acceptance — MVP implementation

- All coverage above passes with the default test command and no external tools.
- Every command works as documented, and documentation lists only commands that work.
- `doctor`, `scan` (Semgrep, ZAP live, ZAP offline) and `compare` honor stdout, stderr and exit-code contracts.
- Semgrep and ZAP fixtures have been checked against real tool output for the pinned versions, or remain explicitly marked `[verify]`.
- Runtime dependencies are `yaml` and `zod` only.
