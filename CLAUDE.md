# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Guardrails is a Claude Code hook framework: a single Go binary (no external dependencies) that consolidates secret scanning, safety guards, branch protection, lint-on-save, and test nudges. It reads Claude Code hook JSON from stdin, runs the checks selected via CLI flags, and communicates results through the hook exit-code contract:

- `0` — allow (optional JSON on stdout injects `additionalContext` warnings)
- `1` — non-blocking error
- `2` — BLOCK (stderr message is fed back to Claude)

Invocation shape: `guardrails --event <pre-tool-use|post-tool-use> --check <comma-separated-checks> [--config path]`

## Commands

```bash
go build ./...                          # build everything
go build -o guardrails-bin ./cmd/guardrails   # build the binary
go test ./...                           # run all tests
go test ./internal/checks/              # test one package
go test ./internal/checks/ -run TestGuardBranch   # run a single test
```

There is no Makefile, CI config, or external linter setup in this repo; `go test ./...` is the verification step.

## Architecture

Data flow: `stdin JSON → cmd/guardrails/main.go (parse + dispatch) → internal/router (validate check names) → internal/checks (pure logic) → exit code`.

- **`cmd/guardrails/main.go`** — the only impure entry point. Parses the hook JSON (`tool_name`, `tool_input`), gathers git context by shelling out (`gitCurrentBranch`, `gitRepoRootForPath`, etc.), normalizes file paths (abs + symlink resolution on the parent dir), then calls into `internal/checks`. The first check that returns `Block: true` exits 2 immediately; warnings from all checks are joined and emitted as a `hookSpecificOutput` JSON allow-with-context response.
- **`internal/checks/`** — one file per check, all returning `checks.CheckResult{Block, Message, Warning}`. Checks are pure functions taking pre-gathered context, which is what makes them unit-testable without git or a filesystem.
- **`internal/config/`** — `config.json` schema and `Default()` fallback. Config is loaded from `--config` or `~/.claude/hooks/guardrails/config.json`; a missing/broken config falls back to defaults with a warning, never a failure.
- **`internal/router/`** — filters requested check names against the valid set (unknown names are silently dropped).
- **`internal/state/`** — persistent JSON edit counter at `~/.claude/hooks/state/.edit-counter` used by test-nudge. Missing or corrupt state files load as a zero counter, never an error.

### The checks

| Check | Event | What it does |
|-------|-------|--------------|
| `secret-scan` | pre | Regex patterns (config-driven) against Bash commands and Write/Edit content; blocks secret-echo commands, inline secrets, and `.env` file creation. `allowPatterns` (env-var references like `os.getenv`) short-circuit to allow. |
| `safety-guard` | pre | Hardcoded block/warn rule tables in `safety_guard.go` for destructive Bash commands (`rm -rf`, force push, `--no-verify`, `sudo`, DROP TABLE, reading sensitive files, …). `git push --force` is special-cased outside the table because Go regexp lacks negative lookahead for `--force-with-lease`. |
| `guard-branch` | pre | The most complex check — see below. |
| `lint` | post | Looks up a linter by file extension in config, runs formatter then linter, feeds errors back as a block so Claude fixes them. Missing linter binaries produce a warning, not a block. |
| `test-nudge` / `test-nudge-reset` | post | Counts edits to non-test source files; warns at `warnAfter`, blocks nothing but escalates at `strongNudgeAfter`. Reset fires when a Bash command matches a configured test command. |

### guard-branch bypass-defense model

`GuardBranch` (internal/checks/guard_branch.go) does far more than compare the current branch name. It runs target-based checks **unconditionally** — even when CWD isn't in a git repo — because writes can escape the working tree:

1. **Temp/non-git script content scan** — scripts written to `/tmp` etc. are scanned for `git commit/push/reset/...` (always blocked) and `git checkout/switch <protected-branch>` (config-driven).
2. **Content path-write scan** — file content anywhere is scanned for shell redirects, `cp/mv/rsync` (destination-aware), Python `open(...,'w')`, Node `fs.writeFile`, and `tee` targeting the protected repo root.
3. **Bash command write scan** — redirects, `tee`, and `--output=`-style write flags targeting the repo path.
4. **Cross-repo check** — a Write/Edit whose target lives in a *different* repo on a protected branch is blocked.
5. Only then: the classic checks — protected branch patterns (anchored `^pattern$` regexes), repo exclusions, staged-changes guard.

When editing this file, preserve the deliberate precision measures: `repoRoot + separator` prefixes (sibling-dir false positives), destination-awareness (repo path as a read source must not block), and `isShellRedirect` exclusions for `>=`, `=>`, `->`. TODO.md tracks the known limitation (pre-compiled binaries with runtime-constructed paths) and the planned OS-level defenses (auditd, AppArmor/SELinux, eBPF).

## Conventions

- Error philosophy: guardrails must never break a Claude Code session. Unparseable stdin exits 0, bad config falls back to defaults, corrupt state loads as zero — failures degrade to "allow", except where the check's purpose is to block.
- Tool-input parsing handles both field spellings everywhere: `file_path`/`path` and `content`/`new_text`.
- Check logic stays in `internal/checks` as pure functions; anything that shells out (git, linters) or touches the filesystem lives in `main.go` or is injected as arguments. Follow this split when adding a check, and register it in `internal/router/router.go` plus the `runCheck` switch in `main.go`.
- Every package has table-driven `_test.go` coverage; new block/warn rules and bypass patterns get corresponding test cases.
- Regexes are compiled at package level (rule tables) or once per call before loops — not inside per-line loops.
