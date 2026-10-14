# 01 — Scope and decisions

Status: approved. Owns: MVP scope, non-goals, runtime, security constraints, limits, responsibility matrix.

## MVP scope

- Commands `doctor`, `scan`, `compare` ([03](03-cli-contract.md)).
- Semgrep over a checked-out directory; ZAP over an already-running HTTP target, live or from an offline alerts dump ([05](05-tool-adapters.md)).
- Redacted raw evidence, one normalized schema, deterministic fingerprints and comparison ([04](04-finding-schema.md)).

## Non-goals

- Modifying source code; interpreting findings with an LLM.
- Installing, starting, stopping or deploying tools or applications (including ZAP and the target app).
- Dynamic or third-party plugins; arbitrary shell commands from configuration.
- Any tool other than Semgrep and OWASP ZAP (no SonarQube).
- Pass/fail gating flags (`--fail-on`); callers read the JSON.
- ZAP active scanning, ZAP report templates, request/response bodies, URL-to-source mapping.
- Config-supplied regular expressions; file output from `compare`.

## Supported tools

| Tool | Target model | Modes |
|---|---|---|
| Semgrep | Source directory inside the repository root | local rules (authoritative), registry IDs, `auto` (non-authoritative) |
| OWASP ZAP | Running HTTP origin; ZAP API on loopback | live scan (spider + passive), offline alerts import |

## Runtime and packaging

- TypeScript, Node.js LTS, npm.
- Runtime dependencies: `yaml`, `zod`. Nothing else.
- Dev dependencies: TypeScript tooling and `ajv` (validates emitted JSON Schema only).
- Built-ins: `util.parseArgs`, `node:test`, `node:crypto`, `node:child_process` (`execFile`), `fetch`.
- Build and bundling tooling is chosen at implementation and must add no runtime dependency.

## Security and operational constraints

- Tool reports, source files, HTTP responses, configuration and repository content are untrusted.
- Allowlisted built-in adapters only. Subprocesses use `execFile` with fixed argv and no shell; only `semgrep` and `git` are ever executed.
- No credentials in config, logs, reports, errors or argv. Config holds environment-variable names and normalized allowed origins only ([03](03-cli-contract.md)).
- ZAP API must be a loopback URL. The target origin must be listed in `allowed_target_origins`; the list is a safety guard, not a security boundary (network isolation is still advised).
- The repository root is the realpath of the working directory. Config, rule files and target must resolve inside it; symlinks are never followed or allowed to escape.
- Artifacts are created exclusively and never overwritten. Redaction fails closed ([02](02-architecture.md)).
- A scan that failed is never confused with a scan with no findings.

## Fixed limits (MVP constants, one source file)

| Limit | Value |
|---|---|
| Text field (title, description, detail) | 4,000 code points |
| Snippet / evidence field | 2,000 code points |
| Identifiers, paths, URLs, methods, parameters, references | see [04](04-finding-schema.md) |
| Source file read for fingerprint | 1 MiB |
| Raw producer JSON | 50 MiB (Semgrep stdout; ZAP bytes across all pages; offline file) |
| `normalized.json` | 25 MiB |
| Findings per scan / occurrences per finding | 10,000 / 100 |
| Target-digest walk | 100,000 files |
| ZAP alerts page size | 500 |
| Semgrep per-rule/per-file timeout | 1–60 s, default 5 |
| Semgrep process timeout | 60–3600 s, default 600 |
| ZAP spider / passive-drain deadline | default 300 s / 120 s, max 3600 s each |

Behavior when a limit is hit is owned by [02](02-architecture.md) (truncation, failure) and [04](04-finding-schema.md) (field shape). Values are revisited with real fixtures.

## Responsibility matrix

| Concern | Scanbridge | Hook / skill | Application | LLM agent |
|---|---|---|---|---|
| Run tools, preserve evidence | yes | | | |
| Start the ZAP daemon and the target app | | yes | yes | |
| Choose when to scan, what to do with results | | yes | | |
| Interpret findings, edit code | | | | yes |
| Gate a pull request | | yes | | |
| Treat findings as data, not instructions | requires it | yes | | yes |
