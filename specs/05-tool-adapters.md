# 05 — Tool adapters

Status: approved. Owns: adapter contract, Semgrep and ZAP behavior, severity mappings, partial classification.

Tags: **[verify]** = taken from source/docs but not yet confirmed against a real tool version; Register: [README](README.md).

## Adapter contract

| Function | IO | Purpose |
|---|---|---|
| `probe(ctx)` | yes | Availability and version; read-only |
| `scan(ctx)` | yes | Execute or query; return bounded raw bytes plus run facts (exit status, timings) |
| `parse(raw)` | no | Raw bytes to a typed producer document, or `malformed_report` |
| `sourceRefs(doc)` | no | Line ranges whose source text is needed for fingerprints (Semgrep); empty for ZAP |
| `normalize(doc, ctx, sources)` | no | Producer document plus pre-read source snippets to findings, diagnostics, completeness |

`ctx` carries validated config, target, injected `Runner`/`HttpClient` (used by `probe` and `scan` only) and limits. `sources` is the result of the orchestration layer reading `sourceRefs` through the injected `SourceReader` ([02](02-architecture.md)); adapters never touch the filesystem. Redaction, fingerprint canonicalization, grouping, sorting and limits are shared `core/` code, not adapter code. Adapters never write files.

## Semgrep

| Aspect | Behavior |
|---|---|
| Availability / version | `semgrep --version` via `execFile`; parsed leniently (format unguaranteed). `producer_version` = JSON `version` when present, else probe value, else null |
| Input | `--target` directory inside the root |
| Invocation | `semgrep scan --json --metrics=off --disable-version-check --disable-nosem --timeout <rule_timeout> --config <rule>… [--exclude <output-base>] <target>`, cwd = root, no shell. Never `--error`, `--verbose`, `--strict` |
| Registry / auto | `--config <id>` or `auto`; `--metrics=off` is omitted because Semgrep requires metrics there; diagnostic `non_deterministic_rules`; reasons `registry_rules` / `auto_rules`; `rules_digest` null **[verify]** (V7) |
| Raw format | `--json` stdout: `results[]`, `errors[]`, `paths.scanned`, optional `version` |
| Process timeout | `timeout_seconds`; SIGTERM, then SIGKILL after 5 s; no usable report gives `failed` + `tool_timeout` |
| Exit status | `0` + parseable JSON: classify below. Any non-zero exit: `failed` + `tool_execution_failed` (stderr tail is redacted, truncated `detail`). Exit 7 behavior **[verify]** |
| Authentication | None for local rules |

`--disable-nosem` is unconditional so a remediation that only adds a `nosemgrep` comment cannot make a finding disappear. The flag exists in Semgrep's CLI source **[verify against pinned version]**.

Normalization: `rule_id` = `check_id`; `title` = rule id, `description` = `extra.message`, `status` always `open`; `severity_original` = `extra.severity`; `confidence`/`category`/`references` only from rule `metadata` when present as expected types; path is the repository-root-relative POSIX path (`--target` limits scope, not the path base); positions from `start`/`end` (offset ignored, it can be a dummy `-1`); snippets arrive pre-read in `sources` and are never read by the adapter; `extra.lines` kept only as redacted evidence; `extra.metavars` removed ([02](02-architecture.md)).

Severity mapping `semgrep-1` (exact, case-sensitive): `CRITICAL→critical`, `HIGH→high`, `ERROR→high`, `MEDIUM→medium`, `WARNING→medium`, `LOW→low`, `INFO→info`, `EXPERIMENT→info`, `INVENTORY→info`. Anything else is `unknown`, reason `unmapped_severity`, diagnostic `unmapped_severity`.

Completeness (exit 0 only). Intentional exclusions (`.gitignore`, `.semgrepignore`, output exclusion) never make a scan partial.

| `errors[]` entry | Result |
|---|---|
| `Timeout`, `Lexical error`, `Syntax error`, `Other syntax error`, `AST builder error`, `PartialParsing`, `Out of memory`, `Stack overflow`, `Fixpoint timeout`, `Timeout during interfile analysis`, `OOM during interfile analysis`, `Too many matches` | partial, `partial_coverage` — takes precedence over `level` |
| `Rule parse error`, `InvalidRuleSchemaError`, `Incompatible rule`, `Pattern parse error`, `Missing plugin` | partial (other rules still ran) |
| `Internal matching error`, `Fatal error` | partial if findings and scanned-file evidence remain, else failed |
| `level: info`; `SemgrepWarning` without known coverage impact | diagnostic only |
| Any other type | partial, `unmapped_error_type` |

Empty or missing `paths.scanned` gives `partial` + `no_files_scanned` (this wins over exclusion logic); empty `results` is authoritative only if at least one file was scanned and not all rules failed. List-encoded types such as `["PartialParsing", …]` **[verify]**.

Limitations: formatting or refactoring can change the snippet and thus the fingerprint; rule content for registry/auto is not pinned; Semgrep's `extra.lines`/`fingerprint` need login and are not relied on.

## OWASP ZAP

ZAP is started and managed outside Scanbridge. API endpoints and parameters below come from ZAP source **[verify]**.

| Aspect | Behavior |
|---|---|
| Availability / version | `GET /JSON/core/view/version/` on a loopback `api_url_env` URL |
| Authentication | Key from `api_key_env`, sent only as `X-ZAP-API-Key`; never in query, logs or reports |
| Input | Target origin (allowlisted). Scope is exactly that origin, not the whole allowlist |
| Raw format | Alerts-API JSON, assembled as `{"alerts":[...]}` from all pages. Traditional JSON reports are unsupported |

Live scan steps:

1. Probe. First keyed action failing: `bad_api_key` or `zap_unreachable_or_rejected` (empty/closed response), exit 2.
2. `session_mode: require_clean`: `numberOfAlerts` for the origin must be 0, else `zap_session_not_clean` (exit 3: no raw artifact and no `normalized.json`; `scan-result.json` is written when the scan directory could be created; the same scan envelope is printed to stdout). `reset` calls `newSession` first (destructive; dedicated local ZAP only); failure stops before contacting the target.
3. Create context `scanbridge-<scan_id>` with an anchored, escaped include regex derived from the origin (not user supplied); run the spider in that context.
4. Wait for spider status 100, then passive `recordsToScan` = `"0"`, each within its deadline.
5. Page `/JSON/alert/view/alerts/` (page 500, `baseurl` = origin); compare alert count before and after paging.
6. Validate every alert URL against the origin; others are excluded and counted in `out_of_scope_target`. Deduplicate and sort before normalization.

Completeness: `complete` only if the spider reached 100, at least one in-scope URL was discovered, passive drain reached 0, all pages were read and the alert count was stable. Deadline hit or Scanbridge-sent stop: `partial` + `tool_timeout`, even if ZAP then reports 100. No in-scope URL: `partial` + `no_urls_discovered`. Count changed while paging: `partial` + `partial_coverage`. API failure before usable evidence: `failed` (3); after: `partial`. `active` is always false; scans are spider plus passive.

Normalization: `rule_id` = ZAP plugin ID; `producer_reference` = `alertRef` after sanitization (null when missing, empty or not a string, with a degraded fingerprint; never derived from the plugin ID or fingerprint, see [04](04-finding-schema.md)); `title` = alert name; entries lacking `pluginId` or `url` are unusable ([04](04-finding-schema.md)); `severity_original` = `risk` text; `confidence` = text, verbatim, never mapped; `runtime_location` = normalized URL, method, param; evidence from `attack`, `evidence`, `other`, `inputVector`, `messageId`. Request/response bodies are not retrieved. No source mapping. Alert field names and casing **[verify]**.

Severity mapping `zap-1` (exact, case-sensitive): `Informational→info`, `Low→low`, `Medium→medium`, `High→high`; anything else `unknown` + `unmapped_severity`. No numeric risk code is read. Applies equally to live and offline input **[verify strings on real ZAP]**.

Offline (`--from-report`): parse and normalize only, `completeness: unverified` ([03](03-cli-contract.md)). `rules_digest` is null because ZAP's installed passive rules cannot be digested in the MVP; `producer_version` is part of reproducibility metadata.

Limitations: ZAP does not expose a reliable difference between an externally stopped spider and a completed one; the allowlist is a guard, not a boundary; capture command for offline dumps is `GET /JSON/alert/view/alerts/` paged and merged as `{"alerts":[...]}`.
