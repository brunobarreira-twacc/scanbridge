# T03 — Redaction engine

Model: Haiku
Status: blocked
Depends on: T01
Parallel group: G1 (with T02, T04, T10)
Branch: ticket/T03-redaction

## Goal

Pure, fail-closed redaction of parsed JSON and plain strings, with a versioned policy.

## Read first

- `specs/02-architecture.md`: Redaction, Scan pipeline steps 5–7
- `specs/01-scope-and-decisions.md`: Security and operational constraints
- `specs/06-testing-and-acceptance.md`: Redaction bullet, Secret canary

## Owns

`src/core/redaction/**`, `tests/unit/redaction/**`.

## Requirements

- `buildPolicy({ headers, json_keys, env_vars }, env: Readonly<Record<string, string | undefined>>): Policy`. Env var names must match `^[A-Za-z_][A-Za-z0-9_]{0,63}$`; values must be at least 8 characters; otherwise throw `PolicyError` naming only the variable and the rule, never the value.
- `Policy.version` = `<BUILTIN_REDACTION_VERSION>+<first 12 hex of sha256>` over a canonical policy JSON: fixed key order, sorted and deduplicated lists, env var names only (never values). Use `JSON.stringify` on that fixed-order object (no dependency on T04).
- `redactTree<T>(value: T, policy: Policy, opts?: { removePaths?: string[] }): { value: T; summary: Record<string, number>; touched: string[] }`.
  - Objects: a key equal (case-insensitive) to `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key` or a configured header name (case-insensitive), or equal (exact case, case-sensitive) to a configured `json_keys` entry, or containing `token`, `password` or `secret` (case-insensitive), has its value replaced. Also treat an object with a string `name` equal to a header name as a header pair and redact its `value`; this is a locked decision.
  - Strings: apply built-in value patterns and exact env values. Patterns with fixed ids: private-key blocks; assignment-style `name = value`, `name: value`, `name=value` (including URL query) where the name contains `token|password|secret|api_key|apikey`; `Bearer <credential>`; and a small documented set (at most 8) of provider token formats, each with its own id. Replacement is `[REDACTED:<rule-id>]`; env values use `[REDACTED:env:<NAME>]`. The exact patterns and rule IDs are fixed in the table below; the implementer adds, removes, renames or loosens none of them (**[verify] V8**).
  - Fixed rule IDs for key and header rules: `header` (built-in and configured header names, including header pairs), `json-key` (configured JSON keys), `key-name` (keys containing `token`, `password` or `secret`). Other fixed IDs: `removed-path`, `env:<NAME>`.
  - `removePaths`: dot paths with `*` wildcard for array or object members (e.g. `results.*.extra.metavars`); matching keys are deleted and counted under id `removed-path`; never record removed values.
  - `touched`: RFC 6901 JSON pointers of every node that was replaced or removed (a removed key reports its parent object).
  - Input is not mutated. Cyclic or non-JSON values throw `RedactionError` (fail closed).
- `redactText(text: string, policy: Policy): { text: string; summary: Record<string, number> }` for source snippets.
- All outputs deterministic; no clock, no IO.

## Fixed value patterns (version `BUILTIN_REDACTION_VERSION` = `"1"`, **[verify] V8**)

Exactly these 12 rules, applied to every string in this order (earlier matches are replaced before later patterns run; env values run last). JavaScript `RegExp` source, flags as listed; every quantifier is bounded so matching is linear and cannot backtrack catastrophically. Changing any pattern or ID requires bumping `BUILTIN_REDACTION_VERSION` in T01's integrator amendment, never in this ticket.

| # | Rule ID | Pattern | Replaced span |
|---|---|---|---|
| 1 | `private-key` | literal 1 below | whole match; an unterminated block is redacted to end of string |
| 2 | `bearer` | literal 2 below | whole match |
| 3 | `provider-github-token` | literal 3 below | whole match |
| 4 | `provider-github-pat` | literal 4 below | whole match |
| 5 | `provider-gitlab-pat` | literal 5 below | whole match |
| 6 | `provider-aws-access-key-id` | literal 6 below | whole match |
| 7 | `provider-slack-token` | literal 7 below | whole match |
| 8 | `provider-google-api-key` | literal 8 below | whole match |
| 9 | `provider-stripe-key` | literal 9 below | whole match |
| 10 | `provider-npm-token` | literal 10 below | whole match |
| 11 | `assignment` | literal 11 below | only the third group (the value); name and separator are kept; covers `name = value`, `name: value`, `name=value` and URL query `?name=value` |
| 12 | `env:<NAME>` | not a regex: exact configured env value, literal substring, longer values first | whole match, replacement `[REDACTED:env:<NAME>]` |

Copy-safe JavaScript regex literals (rules 1–11). In every literal `|` is regex alternation, never a literal pipe; copy them verbatim, do not escape the pipes and do not retype them. The regex flags are part of each literal (`i`, `gi`); rules with no flag are compiled with `g` added by the implementation for replace-all, which changes nothing else.

```js
// 1 `private-key`
const RULE_1 = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,16384}?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)/;
// 2 `bearer`
const RULE_2 = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,512}/gi;
// 3 `provider-github-token`
const RULE_3 = /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/;
// 4 `provider-github-pat`
const RULE_4 = /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/;
// 5 `provider-gitlab-pat`
const RULE_5 = /\bglpat-[A-Za-z0-9_-]{20,50}/;
// 6 `provider-aws-access-key-id`
const RULE_6 = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/;
// 7 `provider-slack-token`
const RULE_7 = /\bxox[abprs]-[A-Za-z0-9-]{10,200}/;
// 8 `provider-google-api-key`
const RULE_8 = /\bAIza[0-9A-Za-z_-]{35}/;
// 9 `provider-stripe-key`
const RULE_9 = /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b/;
// 10 `provider-npm-token`
const RULE_10 = /\bnpm_[A-Za-z0-9]{36}\b/;
// 11 `assignment`
const RULE_11 = /\b([A-Za-z0-9_.-]{0,64}(?:token|password|secret|api_key|apikey)[A-Za-z0-9_.-]{0,64})(\s{0,8}[:=]\s{0,8})("[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|[^\s"'&;,]{1,512})/gi;
```

The provider set (rules 3–10) is small, bounded (8 rules) and not claimed sufficient: mark it `[verify] V8` in the code comment above the table constant. Do not add a ninth provider format.

## Tests (same ticket)

- One synthetic secret per row of the fixed table (one positive case, one near-miss that must not match, e.g. a too-short token), a test that the table has exactly these 12 rule IDs in this order, and a test that no pattern takes more than a bounded time on a 1 MiB adversarial string (e.g. repeated `ghp_` prefixes), plus one fixture per built-in key rule and header rule, asserting the original synthetic secret never appears in the serialized output.
- Env value redaction (exact substring, multiple occurrences), length and name validation errors that do not contain the value.
- `removePaths` with wildcards and `touched` pointers; counts in `summary`; input not mutated.
- Case sensitivity: configured header names match case-insensitively (`x-custom-auth` matches configured `X-Custom-Auth`, also as a `{name, value}` header pair); configured `json_keys` match exact case only (`sessionId` configured does not redact `sessionid`, and does redact `sessionId`); built-in `token`, `password`, `secret` key-name detection stays case-insensitive (`ApiTOKEN`, `PassWord`, `SECRET_x` are redacted).
- Policy version stable for reordered config lists; changes when a header, key or env name is added; independent of env values.
- Fail-closed cases (cyclic structure, `bigint`, function).

## Done when

`npm run build && node --test dist/tests/unit/redaction` passes.

## Verification items

V8 (sufficiency of the built-in value-pattern set) stays `[verify]`: mark it in the pattern table comment and in the test names, and do not claim the set is sufficient.

## Notes

The pattern list is exactly the fixed table above, documented in code comments. No truncation here: truncation happens after redaction in T06.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V8 (pattern table). For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
