package checks

import (
	"regexp"
	"strings"
)

type blockRule struct {
	pattern *regexp.Regexp
	message string
}

type warnRule struct {
	pattern *regexp.Regexp
	message string
}

// Package-level compiled rule slices — block rules exit 2 with descriptive message.
var blockRules = []blockRule{
	// 1. rm -rf or rm -fr
	{
		regexp.MustCompile(`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s`),
		"BLOCKED: 'rm -rf' is not allowed. Use 'trash' for safe deletion, or 'rm' with explicit file paths (no -rf).",
	},
	// 2. rm on root/home directories
	{
		regexp.MustCompile(`rm\s+.*\s+(/|~|/home)\s*$`),
		"BLOCKED: Refusing to delete root, home, or top-level directories.",
	},
	// 3. git reset --hard
	{
		regexp.MustCompile(`git\s+reset\s+--hard`),
		"BLOCKED: 'git reset --hard' destroys uncommitted work. Use 'git stash' to save changes first.",
	},
	// 4. git clean -f
	{
		regexp.MustCompile(`git\s+clean\s+-[a-zA-Z]*f`),
		"BLOCKED: 'git clean -f' permanently deletes untracked files. Use 'git clean -n' (dry run) first.",
	},
	// 5 & 6: git push --force and git push -f are handled specially in SafetyGuard()
	//         to exclude --force-with-lease (Go regexp lacks negative lookahead).
	// 7. git push to protected branches
	{
		regexp.MustCompile(`git\s+push\s+(origin\s+)?(main|master|develop|release|production)\b`),
		"BLOCKED: Direct push to protected branch. Create a feature branch instead.",
	},
	// 8. git add -A or git add --all
	{
		regexp.MustCompile(`git\s+add\s+(-A|--all)\b`),
		"BLOCKED: 'git add -A/--all' stages everything. Stage explicit files instead.",
	},
	// 9. git add .
	{
		regexp.MustCompile(`git\s+add\s+\.\s*$`),
		"BLOCKED: 'git add .' stages everything. Stage explicit files instead.",
	},
	// 10. sudo
	{
		regexp.MustCompile(`(^|\s|;|&&|\|\|)sudo\s`),
		"BLOCKED: sudo is not permitted in Claude Code sessions.",
	},
	// 11. DROP TABLE/DATABASE/SCHEMA or TRUNCATE TABLE (case insensitive)
	{
		regexp.MustCompile(`(?i)(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)`),
		"BLOCKED: Destructive database operation detected (DROP/TRUNCATE).",
	},
	// 12. DELETE FROM without WHERE clause
	{
		regexp.MustCompile(`(?i)DELETE\s+FROM\s+\w+\s*;`),
		"BLOCKED: Destructive database operation: DELETE without WHERE clause.",
	},
	// 13. Reading sensitive files
	{
		regexp.MustCompile(`(cat|less|more|head|tail|bat|vim|nano|code)\s+.*(\.env|id_rsa|id_ed25519|\.pem|\.key|\.secret|credentials|\.npmrc|\.pypirc|\.netrc)`),
		"BLOCKED: Attempted to read a sensitive file. These files contain secrets and MUST NOT be read.",
	},
	// 14. Network tools
	{
		regexp.MustCompile(`(^|\s|;|&&|\|\|)(wget|nc|ncat|netcat|telnet|ftp|sftp)\s`),
		"BLOCKED: Network tool detected. Use the WebFetch tool or MCP servers for web access.",
	},
	// 15. git commit --no-verify
	{
		regexp.MustCompile(`git\s+commit\s+.*--no-verify`),
		"BLOCKED: 'git commit --no-verify' bypasses hooks. Hooks exist for safety — fix the underlying issue instead.",
	},
	// 16. eval
	{
		regexp.MustCompile(`(^|\s|;|&&|\|\|)eval\s`),
		"BLOCKED: 'eval' poses a code injection risk. Use explicit commands instead.",
	},
	// 17. base64 -d piped to sh/bash/zsh/exec
	{
		regexp.MustCompile(`base64\s+-d.*\|\s*(sh|bash|zsh|exec)\b`),
		"BLOCKED: base64 decode piped to shell is an obfuscation risk. Decode to a file and review first.",
	},
	// 18. history or fc -l
	{
		regexp.MustCompile(`(^|\s|;|&&|\|\|)(history|fc\s+-l)\b`),
		"BLOCKED: Shell history may contain secrets. Do not access it.",
	},
}

// Package-level compiled warn rules — allow but inject context.
var warnRules = []warnRule{
	// 1. git push (non-blocked)
	{
		regexp.MustCompile(`git\s+push`),
		"NOTE: Pushing to remote. Verify you are on the correct branch and all tests pass.",
	},
	// 2. rm (non-recursive)
	{
		regexp.MustCompile(`(^|\s)rm\s`),
		"NOTE: Deleting files. Verify these are the correct targets.",
	},
	// 3. chmod or chown
	{
		regexp.MustCompile(`(chmod|chown)\s`),
		"NOTE: Changing file permissions/ownership. Verify this is intentional.",
	},
}

// Patterns for the --force special case (rule 5 & 6).
var gitPushForcePattern = regexp.MustCompile(`git\s+push\s+.*--force`)
var gitPushForceWithLeasePattern = regexp.MustCompile(`--force-with-lease`)
var gitPushDashF = regexp.MustCompile(`git\s+push\s+.*-f\b`)

const forcePushMessage = "BLOCKED: 'git push --force' can overwrite team history. Use 'git push --force-with-lease' instead."

// SafetyGuard checks a command for destructive or dangerous operations.
func SafetyGuard(command string) CheckResult {
	cmd := strings.TrimSpace(command)

	// Special case: git push --force without --force-with-lease (rule 5).
	if gitPushForcePattern.MatchString(cmd) && !gitPushForceWithLeasePattern.MatchString(cmd) {
		return CheckResult{
			Block:   true,
			Message: forcePushMessage,
		}
	}
	// Rule 6: git push -f
	if gitPushDashF.MatchString(cmd) {
		return CheckResult{
			Block:   true,
			Message: forcePushMessage,
		}
	}

	// Check block rules.
	for _, rule := range blockRules {
		if rule.pattern.MatchString(cmd) {
			return CheckResult{
				Block:   true,
				Message: rule.message,
			}
		}
	}

	// Check warn rules — collect all matching warnings.
	var warnings []string
	for _, rule := range warnRules {
		if rule.pattern.MatchString(cmd) {
			warnings = append(warnings, rule.message)
		}
	}

	if len(warnings) > 0 {
		return CheckResult{
			Warning: strings.Join(warnings, " "),
		}
	}

	return CheckResult{}
}
