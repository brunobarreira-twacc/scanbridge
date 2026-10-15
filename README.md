<p align="center">
  <img src="assets/logo.svg" alt="Scanbridge" width="360">
</p>

# Scanbridge

Scanbridge is a small command-line tool that runs a security scanner (today:
**Semgrep**, and **ZAP** reports), turns the results into one stable JSON
format, and lets you **compare two scans** to see what was fixed, what is new,
and what got worse.

Every command prints a single JSON document to stdout, so it is easy to use from
scripts, CI, or an AI agent.

---

## 1. Fastest way to use it: add the skill to your application

This repo ships a ready-made Claude Code skill that drives the CLI for you:

```
.add-in-target-application/
└── deterministic-security-remediation/
    └── SKILL.md
```

The skill scans your code, lets you pick which findings to fix, fixes them one at
a time, and proves each fix by re-scanning and comparing. The CLI is called by
the skill automatically.

### Setup in your application (the one you want to scan)

1. **Copy the skill** into your application's Claude skills folder:

   ```bash
   mkdir -p <your-app>/.claude/skills
   cp -R .add-in-target-application/deterministic-security-remediation \
         <your-app>/.claude/skills/
   ```

2. **Create the launcher the skill expects** at `<your-app>/.pr-review/scanbridge`.
   The skill always calls `./.pr-review/scanbridge`, so this small file points to
   your Scanbridge build:

   ```bash
   mkdir -p <your-app>/.pr-review
   cat > <your-app>/.pr-review/scanbridge <<'EOF'
   #!/usr/bin/env bash
   # SCANBRIDGE_HOME must point to the folder where Scanbridge is cloned and built.
   exec node "${SCANBRIDGE_HOME:?set SCANBRIDGE_HOME to your scanbridge checkout}/dist/src/cli/main.js" "$@"
   EOF
   chmod +x <your-app>/.pr-review/scanbridge
   ```

   Then add this to your shell profile (adjust to where *you* cloned it):

   ```bash
   export SCANBRIDGE_HOME="$HOME/path/to/scanbridge"
   ```

3. **Create the tool config** at `<your-app>/.pr-review/tools.yaml`
   (see [Configuration](#configuration) below).

4. **Ignore the scan output** in your app's `.gitignore`:

   ```
   .scanbridge/
   ```

5. In your app, open Claude Code and run:

   ```
   /deterministic-security-remediation
   ```

   The skill is manual-only (it never starts on its own).

> The skill contains no machine-specific paths. Every path in it is relative to
> your application's root (`./.pr-review/...`, `src`, `.scanbridge/runs`). Your
> app needs a `src` folder, or edit the `--target src` line in the skill to point
> to your code.

---

## 2. Install Scanbridge

You need **Node.js 22 or newer** and **Semgrep** (`brew install semgrep` or
`pipx install semgrep`).

```bash
git clone <this-repo-url> scanbridge
cd scanbridge
npm install
npm run build
```

Check it works:

```bash
node dist/src/cli/main.js doctor --config validation/semgrep/tools.yaml
```

Optional: run it as `scanbridge` from anywhere with `npm link`.

---

## 3. Configuration

Scanbridge reads a YAML file (default: `.pr-review/tools.yaml`). A minimal
Semgrep setup:

```yaml
version: 1

redaction:
  headers: []
  json_keys: []
  env_vars: []

tools:
  semgrep:
    enabled: true
    config:
      rules:
        - .pr-review/rules/my-rules.yaml   # your Semgrep rule files
      rule_timeout_seconds: 5
      timeout_seconds: 600

  zap:
    enabled: false
```

A full working example is in
[`validation/semgrep/tools.yaml`](validation/semgrep/tools.yaml).

---

## 4. Commands

In the examples below `scanbridge` means `node dist/src/cli/main.js` (or the
launcher / `npm link` from above).

### `doctor`: is my scanner ready?

```bash
scanbridge doctor --config .pr-review/tools.yaml
```

Reports whether each enabled tool is installed and usable.

### `scan`: run a scan

Semgrep, on a folder or file:

```bash
scanbridge scan --adapter semgrep --target src --output .scanbridge/runs
```

ZAP, from an existing report (offline):

```bash
scanbridge scan --adapter zap --from-report zap-report.json --output .scanbridge/runs
```

ZAP, against a live URL:

```bash
scanbridge scan --adapter zap --target-url https://staging.example.com --output .scanbridge/runs
```

| Option | Meaning |
| --- | --- |
| `--adapter` | `semgrep` or `zap` (required) |
| `--output` | Folder where results are saved (required) |
| `--target` | Path to scan (Semgrep only) |
| `--target-url` | URL to scan (ZAP only) |
| `--from-report` | Existing ZAP report to import (ZAP only) |
| `--target-revision`, `--producer-version` | Optional labels for ZAP reports |
| `--config` | Config file (default `.pr-review/tools.yaml`) |

The JSON result tells you where the files were written
(`artifacts.directory`, `artifacts.normalized`), plus `status` (`complete` or
partial) and `authoritative` (`true` means you can trust it as proof).

### `compare`: what changed between two scans?

```bash
scanbridge compare \
  --base-report .scanbridge/runs/<before>/normalized.json \
  --head-report .scanbridge/runs/<after>/normalized.json
```

Findings are grouped as **resolved**, **new**, **changed**, **severity
increased** or **incomparable**. Add `--allow-partial` to accept incomplete scans
(the result will then not be authoritative).

> Use the exact file path given by `artifacts.normalized` in the scan output; the
> `<before>`/`<after>` names above are placeholders.

---

## 5. Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Wrong arguments or invalid configuration |
| `2` | A tool (e.g. Semgrep) is not available |
| `3` | The scan failed |
| `4` | Partial result refused (use `--allow-partial` on `compare` to override) |
| `5` | Invalid or incompatible report |

---

## 6. Development

```bash
npm run build        # compile TypeScript to dist/
npm test             # build + unit and contract tests
npm run typecheck    # type-check only
npm run gen:schemas  # regenerate JSON schemas in schemas/
```

Design documents live in [`specs/`](specs/).
