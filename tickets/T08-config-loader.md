# T08 — Configuration loader

Model: Haiku
Status: blocked
Depends on: T01, T03, T04
Parallel group: G2
Branch: ticket/T08-config

## Goal

Load and strictly validate `.pr-review/tools.yaml`, resolve environment-derived ZAP inputs (including the API key held in memory only), and compute `configuration_digest` and `rules_digest`.

## Read first

- `specs/03-cli-contract.md`: Configuration section, ZAP input rule, `doctor` bullets, `scan` flag rules
- `specs/01-scope-and-decisions.md`: Security constraints, Fixed limits (timeouts)
- `specs/04-finding-schema.md`: `rules_digest` row, ZAP URL normalization (via T04 `normalizeOrigin`/`normalizeUrl`)
- `specs/02-architecture.md`: Redaction (env var rules)
- `src/contracts/sensitive.ts` and `adapter.ts` (T01)

## Owns

`src/config/**`, `tests/unit/config/**`, `tests/fixtures/config/**`.

## Requirements

- `loadConfig(path, { root, env }): { ok: true; config: Config } | { ok: false; errors: ConfigError[] }`. Reads the file with `yaml`; the schema is strict at every level with `version: 1`.
- Redaction section: `headers`, `json_keys`, `env_vars` (names validated with T03 rules; values checked for at least 8 characters through the injected `env`; errors name the variable only).
- Semgrep: exactly one of non-empty `rules`, non-empty `registry_ids`, `use_auto: true`; `rule_timeout_seconds` 1–60 (default 5); `timeout_seconds` 60–3600 (default 600). Rule paths are repository-relative files: realpath inside `root`, existing, a file (not a directory), no symlink escape.
- ZAP: `api_url_env`, `api_key_env`, `target_url_env` must match the env-name pattern `^[A-Za-z_][A-Za-z0-9_]{0,63}$` (so a URL placed there is rejected); `allowed_target_origins` normalized with `normalizeOrigin`; `session_mode` `require_clean | reset` (default `require_clean`); `active` accepts only `false`; `spider_timeout_seconds` (default 300) and `passive_timeout_seconds` (default 120), each 1–3600.
- Config must not carry: the selected target URL or the ZAP API URL (no field exists for them, so the strict schema rejects them); credentials; any URL with user information (reject any string value containing `scheme://user@`); a URL in a field that should hold an environment-variable name. The config may contain normalized `allowed_target_origins`, and nothing else URL-like. Do not reject URLs generally.
- Config errors never echo secret values.
- Purpose-specific ZAP input resolution. There is no combined `resolveZapInputs`. Three functions, each taking `{ config, env }` (plus `flags: { targetUrl?: string }` where listed) and returning a plain object with `problems: { source: 'env' | 'flag', code, message }[]` (empty means the purpose is satisfied; fields that could not be resolved are `null`):
  - `resolveZapDoctorInputs({ config, env }): { apiUrl: string | null; apiKey: SensitiveString | null; apiKeyPresent: boolean; problems }`. Reads only `api_url_env` and `api_key_env`. Never reads `target_url_env`, takes no flags and never reports a missing target as a problem.
  - `resolveZapLiveInputs({ config, env, flags }): { apiUrl: string | null; apiKey: SensitiveString | null; targetUrl: string | null; targetUrlOverridden: boolean; problems }`. Needs API URL, API key and target URL. The flag wins over `target_url_env` and sets `targetUrlOverridden`.
  - `resolveZapOfflineInputs({ config, env, flags }): { targetUrl: string | null; targetUrlOverridden: boolean; problems }`. Needs only the target URL (flag wins over `target_url_env`). Never reads `api_url_env` or `api_key_env`, and has no API URL or key field.
- Common rules: the key is read from the environment variable named by `api_key_env` and wrapped in `SensitiveString` immediately. It is never logged, persisted, copied into `problems` or messages, included in digests, or included in any diagnostic. `apiKeyPresent` is true when the variable is set and non-empty. Missing or invalid values from env give exit class 2 (diagnostic `tool_unavailable`); invalid flag values give class 1. Checks: API URL loopback (127.0.0.0/8, `::1`, `localhost`), API key variable set, target URL valid and its origin in `allowed_target_origins`. Each function runs only the checks of its purpose; session checks are not part of resolution.
- `configurationDigest({ tool, config, redactionPolicyInput, ruleFiles })`: SHA-256 of `canonicalJson` of the validated tool section plus effective redaction policy plus sorted `(relative path, SHA-256 of file bytes)` pairs. Env values and the API key are never included.
- `rulesDigest(ruleFiles)`: SHA-256 of `canonicalJson` of the sorted `(relative path, SHA-256)` pairs for local rules; `null` for registry and `auto` modes. **[verify] V7**: a resolved-rule digest for registry/auto is not derived; `null` stays until verified.
- Rule file bytes are read by the loader, not by the digest functions.

## Tests (same ticket)

- Valid minimal and full configs; every rejection (unknown key at each level, version not 1, two rule modes, none, directory as rule, escaping path, symlink escape, bad timeout bounds (**[verify] V9** constants from T01), `active: true`, URL in an env-name field, userinfo URL anywhere, bad origin entries, short env value, bad env name). A plain allowed origin is accepted.
- `resolveZapDoctorInputs`: key and URL present; key missing (`apiKeyPresent` false, problem); non-loopback API URL; the target variable unset or invalid never produces a problem and is never read (assert with an env reader that throws on `target_url_env`).
- `resolveZapLiveInputs`: flag wins and sets `targetUrlOverridden`; neither target source present; non-loopback API URL from env versus invalid flag; origin not allowlisted from env versus flag; missing key.
- `resolveZapOfflineInputs`: target from flag, from env, override, neither; origin not allowlisted; an env reader that throws on `api_url_env` and `api_key_env` proves they are never read; the result has no API key or API URL field; targetUrl remains present.
- Across all three: the wrapped key cannot be revealed through `JSON.stringify`, `String`, `util.inspect`, problems, or digests; a canary key value never appears anywhere except via `reveal()`.
- Digests stable for reordered keys, change with rule content or config, ignore env values and the key; `rulesDigest` is null for registry and auto.

## Done when

`npm run build && node --test dist/tests/unit/config` passes.

## Verification items

V7 (registry/auto rules digest) and V9 (timeout bounds) stay `[verify]`.

## Notes

Loopback and URL checks use only parsing, no network. This module may read files; `core/` may not.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V7, V9. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
