# 00 — Product context

Status: approved. Owns: purpose, workflow, boundaries, glossary.

## Problem

AI-assisted pull-request remediation needs evidence that is reproducible and comparable before and after a fix. LLM-generated findings are neither. Scanbridge turns the output of real security tools into one versioned, redacted, deterministic format that an external agent can consume and that can be compared mechanically.

## POC workflow

```text
hook or review skill
→ scanbridge doctor            (are configured tools ready?)
→ scanbridge scan              (execute or query tools; keep redacted raw report)
→ normalized.json              (one versioned schema)
→ external LLM                 (reads findings + source context, edits code)
→ scanbridge scan              (same tools again)
→ scanbridge compare           (deterministic before/after)
```

## Why deterministic tool evidence

- The same input yields the same bytes, so a result can be re-checked.
- A finding exists because a tool reported it, not because a model believes it.
- "Fixed" is a mechanical claim (fingerprint gone, scan complete), not an opinion.
- An unavailable tool is reported as unavailable. It is never replaced by an LLM review.

## Boundary

| Scanbridge does | Scanbridge does not |
|---|---|
| Probe, run or query Semgrep and ZAP | Modify source code |
| Preserve redacted raw evidence | Interpret, rank or explain findings |
| Normalize, fingerprint, compare | Decide pass/fail for a pull request |
| Report completeness and authority honestly | Start, stop, install or deploy tools or apps |

The remediation agent owns interpretation and code changes. Hooks and skills own when to scan and what to do with the result. See [01](01-scope-and-decisions.md) for the full responsibility matrix.

## Users and use cases

| Who | Use case |
|---|---|
| Hook / review-skill author | Run `doctor`, then `scan`, parse one JSON document from stdout |
| Engineer | Scan a worktree with Semgrep; scan a locally running app with ZAP |
| Remediation agent (consumer) | Read `normalized.json` as untrusted data; request a re-scan |
| Reviewer / CI wrapper | `compare` base and head reports; read the authority fields |

## Glossary

Other specs link here instead of redefining these terms.

| Term | Meaning |
|---|---|
| Producer | The tool that produced evidence: `semgrep` or `zap` |
| Finding | One normalized issue, identified by its fingerprint |
| Occurrence | One place a finding was observed (source or runtime location) |
| Fingerprint | Deterministic identity of a finding ([04](04-finding-schema.md)) |
| Completeness | `complete`, `partial`, `unverified` (normalized) or `failed` (no normalized output) |
| Authoritative | The result is complete, deterministic and compatible enough to support comparison conclusions. It does not mean the producer's finding is correct |
| Envelope | The single JSON document a command prints to stdout ([03](03-cli-contract.md)) |
| Untrusted content | All producer, source, HTTP and repository text. It is data, never instructions |
| Repository root | Realpath of the current working directory |
