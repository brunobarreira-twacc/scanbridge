# 03 — CLI contract

Status: approved. Owns: commands, arguments, validation, stdout/stderr, exit codes, envelopes, configuration file.

## Global rules

- Stdout carries exactly one JSON document plus a newline, on every path. `scan` prints exactly the content of `scan-result.json`. Stderr carries human logs; it never carries secrets, target URLs with credentials, or headers.
- Repository root = realpath of the working directory. Run from the repo root.
- `--config` defaults to `.pr-review/tools.yaml` for `doctor` and `scan`. `compare` loads no config.
- Unknown flags are usage errors. Parsing uses `util.parseArgs` in strict mode.

## Output directory (`--output`)

- Must resolve (realpath) to a directory; a missing base is created, then validated with the same realpath and symlink checks as other paths. A non-directory is a usage error (1).
- For Semgrep it must not equal `--target` (usage error, 1).
- When it is a descendant of the Semgrep target, the complete output base directory (not just `<scan_id>`) is excluded from the target-content digest and from Semgrep, using its normalized target-relative path (`--exclude`).
- This is an intentional exclusion: it does not make the scan partial and does not affect `rules_digest`. It is recorded in `scan-result.json` `exclusions[]`.
- Artifacts from earlier Scanbridge runs must never become scan inputs. An existing `<output>/<scan_id>` is never overwritten ([02](02-architecture.md)).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success: ready; scan `complete` or `unverified`; comparison produced (even non-authoritative) |
| 1 | `usage_error` or `invalid_configuration` |
| 2 | Tool unavailable or readiness failed (includes `bad_api_key`, `zap_unreachable_or_rejected`), before scanning began |
| 3 | Scan failed (execution failure, no usable evidence, `zap_session_not_clean`, `redaction_failed`, limits, bad offline input) |
| 4 | Scan `partial`; or `compare` refused a partial input (`partial_input_refused`) |
| 5 | `compare` input invalid (`invalid_report`) or incompatible (`incompatible_reports`) |

Exit 1 and 5 print an error envelope. Exits 2–4 for `scan` print the scan envelope with `status` set accordingly.

ZAP input rule: a required ZAP value obtained from an environment variable (API URL, API key, or target URL when no flag is given) that is missing or invalid (malformed, non-loopback API URL, origin not in `allowed_target_origins`) exits 2 with a `tool_unavailable` diagnostic, because the configured integration is not ready. The same invalid value given by a CLI flag or static configuration exits 1. Offline mode skips only the live-only requirements (API URL, API key, session state); its target URL follows this rule.

## Commands

### `doctor`

```bash
scanbridge doctor [--config <path>] [--json]
```

- Read-only readiness check; never scans. `--json` is a no-op (stdout is always JSON).
- Validates config first (exit 1 on failure, including missing or escaping local rule paths).
- Semgrep: runs `semgrep --version` (no shell). ZAP: requires the API URL (env) to be loopback and the key env var to be set, then performs exactly one `GET /JSON/core/view/version/` (short timeout, no redirects, key in `X-ZAP-API-Key` header only).
- Disabled tools are `skipped`. Exit 0 if every enabled tool is ready, else 2.

```json
{"schema_version":"1","command":"doctor","ok":true,"tools":[
 {"name":"semgrep","status":"ready","version":"1.x.y","problems":[]},
 {"name":"zap","status":"ready","version":"2.x.y","api_key":"present","api_key_verified":false,"problems":[]}]}
```

`problems[]` entries are `{code, message}` using diagnostic codes ([04](04-finding-schema.md)). Environment-derived invalid values (non-loopback API URL, missing key variable) are readiness failures (exit 2), not configuration errors.

### `scan --adapter semgrep`

```bash
scanbridge scan --adapter semgrep --target <dir> --output <dir> [--config <path>]
```

`--target` must be an existing directory inside the root. `--target-url`, `--from-report` are usage errors.

### `scan --adapter zap` (live)

```bash
scanbridge scan --adapter zap --target-url <url> --output <dir> [--config <path>] [--target-revision <s>]
```

- Target URL from `--target-url` or the env var named by `target_url_env`; the flag wins and adds an info diagnostic `target_url_overridden` (also on stderr).
- URL rules: http/https only; no user info, no fragment; origin normalized, then required to be exactly in `allowed_target_origins`. `--target` is a usage error.
- `--target-revision` is caller-asserted metadata; length ≤ 128, characters `[A-Za-z0-9._/@:+-]`.

### `scan --adapter zap --from-report` (offline)

```bash
scanbridge scan --adapter zap --from-report <file> [--target-url <url>] --output <dir> \
  [--config <path>] [--target-revision <s>] [--producer-version <s>]
```

- A target URL is required but may come from `--target-url` or the env var named by `target_url_env`; the flag wins and adds `target_url_overridden`. Neither present: exit 2 (ZAP input rule above).
- `--config` (default as in Global rules) supplies `allowed_target_origins`, `target_url_env` and redaction settings. The target origin must be listed there, and every alert URL is checked against that origin.
- No ZAP API call; `api_url_env`, `api_key_env` and session state are not validated; no context, spider or passive wait.
- File ≤ 50 MiB, exactly `{"alerts":[...]}`; read and redacted in memory, never persisted unredacted.
- Result: `completeness: unverified`, `authoritative: false`, reason `offline_report`, exit 0.
- `--target-revision` is supported with the live validation; it is stored as caller-asserted `target.asserted_revision` and never verified ([07](07-comparison.md)). `--producer-version` (same validation) is caller-asserted; otherwise `producer_version` is null.
- Malformed, unsupported (e.g. Traditional JSON report) or oversized input exits 3 with no raw and no normalized artifact. `scan-result.json` is still written when the scan directory could be created, and the envelope is always printed.
- Live-only flags together with `--from-report` are usage errors.

### `compare`

```bash
scanbridge compare --base-report <normalized.json> --head-report <normalized.json> [--allow-partial] [--json]
```

- Stdout only; no file output. `--json` is a no-op. Semantics, `findings[]` entries and authority: [07](07-comparison.md).
- Inputs are schema-validated first. Invalid or unsupported schema version: `invalid_report` (5). Different producers: `incompatible_reports` (5).
- An input with `completeness: partial` without `--allow-partial`: `partial_input_refused` (4). `unverified` inputs need no flag.
- Output: `{command:"compare", authoritative, non_authoritative_reasons[], base:{...}, head:{...}, summary{...}, findings[]}`; `base`/`head` repeat each input's producer version, completeness and original authority reasons.

## Envelopes

Error envelope (exit 1, 4-refused, 5):

```json
{"schema_version":"1","status":"error","error":{"code":"invalid_report","message":"head report failed schema validation"}}
```

Codes: `usage_error`, `invalid_configuration` (1); `partial_input_refused` (4); `invalid_report`, `incompatible_reports` (5). Messages are Scanbridge-authored; producer text never appears here.

Scan envelope (`scan-result.json`):

```json
{"schema_version":"1","command":"scan","status":"partial","exit_code":4,"scan_id":"20261013T142501.123Z-3fa9c0d1",
 "adapter":"semgrep","started_at":"…","finished_at":"…","duration_ms":8123,
 "authoritative":false,"non_authoritative_reasons":["partial_scan"],
 "findings_count":3,"exclusions":[],
 "diagnostics":[{"code":"partial_coverage","level":"warn","tool":"semgrep","message":"Some files were not fully analyzed.",
   "detail":{"text":"…","truncated":false,"original_length":42,"untrusted":true}}],
 "artifacts":{"directory":"<output>/<scan_id>","raw":["raw/semgrep.json"],"normalized":"normalized.json"}}
```

`status`: `complete | partial | unverified | failed`. `artifacts` fields are omitted or `null` when absent. Run-specific data (id, times, paths, diagnostics) lives only here, never in `normalized.json`.

## Unavailable tools and partial scans

- An unavailable or disabled-then-requested tool is reported, never replaced by an LLM review. Scanning a disabled adapter is a usage error (1).
- Partial scans write all evidence, set `status: partial`, exit 4. Classification rules per tool: [05](05-tool-adapters.md).

## Configuration: `.pr-review/tools.yaml`

Strict: unknown keys are rejected at every level; `version` must be `1`. Secrets are never stored: config holds environment-variable names, never their values.

- `allowed_target_origins` may hold normalized origins only (`scheme://host[:port]`, http/https, normalized per [04](04-finding-schema.md)); entries with user information, path, query or fragment are rejected (exit 1).
- Config must not contain the selected target URL, the ZAP API URL, or credentials or user information inside any URL. Those come from flags or the named environment variables.

```yaml
version: 1
redaction:                       # additions only; built-ins always apply
  headers: []                    # exact header names
  json_keys: []                  # exact JSON key names
  env_vars: []                   # names of variables whose values are redacted (>= 8 chars)
tools:
  semgrep:
    enabled: true
    config:
      rules: [rules/security.yaml]   # exactly ONE of: rules | registry_ids | use_auto
      # registry_ids: ["p/ci"]       # non-authoritative
      # use_auto: true               # non-authoritative
      rule_timeout_seconds: 5
      timeout_seconds: 600
  zap:
    enabled: true
    config:
      api_url_env: SCANBRIDGE_ZAP_API_URL
      api_key_env: SCANBRIDGE_ZAP_API_KEY
      target_url_env: SCANBRIDGE_ZAP_TARGET_URL
      allowed_target_origins: ["http://127.0.0.1:8080"]   # normalized origins only
      session_mode: require_clean    # or: reset (destructive)
      active: false                  # only false is accepted in the MVP
      spider_timeout_seconds: 300
      passive_timeout_seconds: 120
```

- Rule modes are mutually exclusive; combining them or none is exit 1. `rules` are repository-relative rule files inside the root. There are no exclusion globs: Semgrep's standard ignore behavior plus the mandatory output exclusion only.
- Superseded prompt example: `rules: auto` becomes `use_auto: true`.
- `configuration_digest` = SHA-256 of canonical validated config for the tool, the effective redaction policy, and `(relative path, SHA-256)` of each local rule file. Env values are never included.
