# Guardrails

A Claude Code hook framework that consolidates secret scanning, safety guards, branch protection, lint-on-save, and test nudge into a single Go binary.

## Checks

| Check | Event | Description |
|-------|-------|-------------|
| `secret-scan` | PreToolUse | Blocks hardcoded secrets, env var leaks, `.env` file creation |
| `safety-guard` | PreToolUse | Blocks destructive commands (`rm -rf`, force push, `--no-verify`, etc.) |
| `guard-branch` | PreToolUse | Blocks writes on protected branches (main, master, develop, release/*) |
| `lint` | PostToolUse | Auto-detects and runs linter by file extension, feeds errors back to Claude |
| `test-nudge` | PostToolUse | Escalating reminders to run tests after N source file edits |

## Installation

```bash
# Clone and build
git clone https://github.com/AvogadroSG1/guardrails.git ~/.claude/hooks/guardrails
cd ~/.claude/hooks/guardrails
go build -o ~/.claude/hooks/guardrails-bin ./cmd/guardrails

# Copy and customize config
cp config.json ~/.claude/hooks/guardrails/config.json
```

## Usage

The binary reads hook JSON from stdin and uses CLI flags for routing:

```
stdin (JSON) --> guardrails --event <pre-tool-use|post-tool-use> --check <checks> --> stdout/stderr
```

Exit codes follow the Claude Code hook contract:
- `0` — allow (optional JSON on stdout for context injection)
- `1` — non-blocking error
- `2` — BLOCK (stderr message fed back to Claude)

## Hook Wiring

Add to your `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "~/.claude/hooks/guardrails-bin --event pre-tool-use --check secret-scan,safety-guard" }]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "~/.claude/hooks/guardrails-bin --event pre-tool-use --check guard-branch,secret-scan" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "~/.claude/hooks/guardrails-bin --event post-tool-use --check lint,test-nudge" }]
      },
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "~/.claude/hooks/guardrails-bin --event post-tool-use --check test-nudge-reset" }]
      }
    ]
  }
}
```

## Configuration

All thresholds and patterns are tunable via `config.json`. See the included file for defaults.

## Testing

```bash
go test ./...
```

## License

MIT
