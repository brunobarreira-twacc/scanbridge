# T09 — IO port implementations

Model: Haiku
Status: blocked
Depends on: T01, T04
Parallel group: G2
Branch: ticket/T09-io-ports

## Goal

Real implementations of the injected ports: `Runner`, `HttpClient`, `SourceReader`, `TargetIdentityReader`, plus simple `Clock` and `EnvReader`.

## Read first

- `specs/02-architecture.md`: Components, orchestration ports paragraph
- `specs/04-finding-schema.md`: Target digest paragraph, Fingerprints (unreadable source)
- `specs/05-tool-adapters.md`: Semgrep process timeout row, ZAP Authentication row
- `specs/01-scope-and-decisions.md`: Security constraints, Fixed limits
- `src/contracts/ports.ts` (from T01)

## Owns

`src/adapters/io/**` (Runner, HttpClient), `src/cli/ports/**` (SourceReader, TargetIdentityReader, Clock, EnvReader), `tests/unit/io/**`, `tests/unit/ports/**`.

## Requirements

- `NodeRunner`: `execFile` (never a shell), only the commands `semgrep` and `git`; `cwd` set; stdout bounded by `maxStdoutBytes` (stop reading, set `stdoutTruncated`); `stderrTail` limited to the last 2 KiB; on timeout send SIGTERM, then SIGKILL after 5 s, set `timedOut`; `spawnFailed` when the binary is missing. Environment passes through unchanged except nothing is logged.
- `FetchHttpClient`: GET only, `redirect: 'manual'`, timeout through `AbortSignal`, body read with a byte cap and `truncated` flag, plain `headers` plus `sensitiveHeaders` (`SensitiveString` values revealed only here, via `.reveal()`, when building the request; never logged, never included in errors, thrown messages or returned values; this is the only place `.reveal(` may appear). An empty or closed connection with no response gives `{ kind: 'closed' }`; timeouts `{ kind: 'timeout' }`; other failures `{ kind: 'error', code }`.
- `FsSourceReader(rootAbs, targetRel)`: reads a root-relative path inside the target; reject `..`, absolute paths and any path whose realpath leaves the target (`outside_target`); do not follow symlinks (`symlink`, check each component with `lstat`); more than 1 MiB gives `too_large`; invalid UTF-8 (`TextDecoder` with `fatal`) gives `invalid_utf8`; missing file `missing`; other errors `unreadable`; returns the complete line range as text with LF-joined lines.
- `FsTargetIdentityReader`: for a git worktree (detected via `Runner` `git rev-parse --is-inside-work-tree`) uses `rev-parse HEAD`, `status --porcelain -- <target>` (non-empty means dirty) and `ls-files -z --cached --others --exclude-standard -- <target>`; for other directories walks the tree. Digest per spec 04: sorted records `(relative path, entry type, executable bit, content sha256)` as a canonical JSON array hashed with SHA-256; symlinks hashed by link text, never followed; `.git` and every `excludeRel` directory excluded; more than 100,000 entries or a read error gives `content_digest: null` and a `target_identity_unavailable` diagnostic. Non-git targets report `revision: null`, `dirty: null`.
- `SystemClock`, `ProcessEnv` thin wrappers.

## Tests (same ticket)

- Runner with `node` itself as the child command via a test-only allowlist override: successful output, non-zero exit, timeout kill with a sleeping child, stdout cap, missing binary. (Production allowlist stays `semgrep`/`git`; expose the allowlist as a constructor parameter defaulting to it.)
- HttpClient against an in-process `127.0.0.1` server: normal response, 302 not followed, slow response timeout, oversized body, connection destroyed before response; a sensitive header reaches the server but a canary value never appears in any returned value or error.
- SourceReader on temp directories: normal range, last line without newline, outside path, symlink file, symlinked directory component, 1 MiB boundary (at and over), invalid UTF-8, missing file.
- TargetIdentity with a fake `Runner` for the git branch (dirty and clean, scoped paths) and real temp trees for the directory branch: digest stable across runs, changes with content or exec bit or symlink target, excludes `.git` and output directories, walk cap behavior using a lowered injectable cap.

## Done when

`npm run build && node --test dist/tests/unit/io dist/tests/unit/ports` passes with no external tool installed.

## Verification items

V9 (read cap 1 MiB, stdout cap, response cap, 100,000-entry walk cap, timeouts) stays `[verify]`: use only `src/contracts/limits.ts` constants and test one below, at and one above each.

## Notes

Optional split if the session runs long: `adapters/io` (Runner, HttpClient) versus `cli/ports` (the rest).

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V9. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
