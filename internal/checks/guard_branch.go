package checks

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

// TargetInfo holds information about the file or command being executed,
// used by the new bypass-detection phases.
type TargetInfo struct {
	FilePath string // absolute path of file being written (Write/Edit tools)
	Branch   string // git branch of the repo at FilePath (empty if not in a repo)
	RepoRoot string // git root of the repo at FilePath (empty if not in a repo)
	Content  string // file content being written
	Command  string // bash command string (Bash tool only)
}

var knownTempDirs = []string{"/tmp/", "/var/tmp/", "/private/tmp/"}

// tempAlwaysBlockPatterns matches git operations that are always dangerous
// when found in scripts written to temp or non-git paths.
var tempAlwaysBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)git\s+commit\b`),
	regexp.MustCompile(`(?i)git\s+push\b`),
	regexp.MustCompile(`(?i)git\s+reset\b`),
}

var tempCheckoutPattern = regexp.MustCompile(`(?i)git\s+(checkout|switch)\s+`)

// contentWritePatterns detects write operations in file content targeting an
// absolute path. Used to catch scripts (at any location) that output into the
// guarded project directory.
var contentWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`open\s*\(`),                       // Python open()
	regexp.MustCompile(`fs\.(writeFile|appendFile)\s*\(`), // Node.js
	regexp.MustCompile(`>\s*\S`),                          // shell redirect
	regexp.MustCompile(`\b(cp|mv|rsync)\s+`),              // copy/move
}

// contentReadOnlyPatterns matches operations that only read; used to suppress
// false positives from contentWritePatterns.
var contentReadOnlyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bcat\s+`),
	regexp.MustCompile(`open\s*\(.*,\s*['"]r['"]\s*\)`), // Python open(..., 'r')
}

// bashWriteFlagPatterns detects non-redirect write operators in Bash commands
// that precede the target path (tee, common CLI write flags).
var bashWriteFlagPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\|\s*tee\b`),
	regexp.MustCompile(`(?i)(--output|-o\b|--file|--target|--write(?:-to)?)`),
}

func isTempPath(path string) bool {
	for _, dir := range knownTempDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	if t := os.TempDir(); t != "" && strings.HasPrefix(path, t) {
		return true
	}
	return false
}

// checkTempOrNonGitContent scans file content for git manipulation commands.
// Tier-1: always block commit/push/reset. Tier-2: block checkout/switch only
// when targeting a protected branch from cfg.
func checkTempOrNonGitContent(content string, cfg config.Config) CheckResult {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		for _, re := range tempAlwaysBlockPatterns {
			if re.MatchString(line) {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("Script in temp/non-git path contains git manipulation command: %q", truncate(line, 120)),
				}
			}
		}

		if tempCheckoutPattern.MatchString(line) {
			for _, pattern := range cfg.ProtectedBranches {
				re, err := regexp.Compile(`(?i)git\s+(checkout|switch)\s+(-b\s+)?` + pattern + `\b`)
				if err != nil {
					continue
				}
				if re.MatchString(line) {
					return CheckResult{
						Block:   true,
						Message: fmt.Sprintf("Script in temp/non-git path targets protected branch %q: %q", pattern, truncate(line, 120)),
					}
				}
			}
		}
	}
	return CheckResult{}
}

// checkContentForPathWrites scans file content for write operations targeting
// repoRoot, to detect scripts written anywhere that output into the guarded project.
func checkContentForPathWrites(content, repoRoot string) CheckResult {
	if repoRoot == "" {
		return CheckResult{}
	}
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, repoRoot) {
			continue
		}
		// Skip lines that are clearly read-only.
		readOnly := false
		for _, re := range contentReadOnlyPatterns {
			if re.MatchString(line) {
				readOnly = true
				break
			}
		}
		if readOnly {
			continue
		}
		for _, re := range contentWritePatterns {
			if re.MatchString(line) {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("File content writes to protected repo %q: %q", repoRoot, truncate(line, 120)),
				}
			}
		}
	}
	return CheckResult{}
}

// checkBashCommandForWrites detects shell redirects or write-flag patterns in a
// Bash command that target the protected repo path. It inspects the portion of
// the command before the first appearance of repoRoot to find write operators.
func checkBashCommandForWrites(command, repoRoot string) CheckResult {
	if repoRoot == "" || !strings.Contains(command, repoRoot) {
		return CheckResult{}
	}
	repoIdx := strings.Index(command, repoRoot)
	before := command[:repoIdx]

	// Shell redirect: the portion before repoRoot ends with > or >> (after trimming whitespace).
	trimmed := strings.TrimRight(before, " \t")
	if strings.HasSuffix(trimmed, ">") || strings.HasSuffix(trimmed, ">>") {
		return CheckResult{
			Block:   true,
			Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
		}
	}

	// Other write operators: tee, common write flags.
	for _, re := range bashWriteFlagPatterns {
		if re.MatchString(before) {
			return CheckResult{
				Block:   true,
				Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
			}
		}
	}
	return CheckResult{}
}

// GuardBranch checks if writes should be allowed based on branch, repo state,
// and target file/command context.
func GuardBranch(branch string, repoRoot string, hasStagedChanges bool, cfg config.Config, target TargetInfo) CheckResult {
	// 1. Empty branch means detached HEAD — allow.
	if branch == "" {
		return CheckResult{}
	}

	// 2. Check repo exclusions from config.
	for _, excl := range cfg.RepoExclusions {
		if strings.HasPrefix(repoRoot, excl) {
			return CheckResult{}
		}
	}

	// 3. Default exclusion: ObsidianNotes repos are always allowed.
	if strings.Contains(repoRoot, "ObsidianNotes") {
		return CheckResult{}
	}

	// 4. Check protected branches.
	for _, pattern := range cfg.ProtectedBranches {
		re, err := regexp.Compile("^" + pattern + "$")
		if err != nil {
			continue
		}
		if re.MatchString(branch) {
			return CheckResult{
				Block:   true,
				Message: fmt.Sprintf("Branch %q is protected. Protected branches: %s", branch, strings.Join(cfg.ProtectedBranches, ", ")),
			}
		}
	}

	// 5. Check for staged changes.
	if hasStagedChanges {
		return CheckResult{
			Block:   true,
			Message: "Repository has staged changes. Please commit or stash manual changes first.",
		}
	}

	// 6a. Temp-dir / non-git content scan: detect git manipulation in scripts
	//     written to locations that bypass the normal branch check.
	if target.FilePath != "" && target.Content != "" &&
		(isTempPath(target.FilePath) || target.RepoRoot == "") {
		if r := checkTempOrNonGitContent(target.Content, cfg); r.Block {
			return r
		}
	}

	// 6b. Content scan for writes to the guarded repo path (any file, anywhere).
	if target.Content != "" {
		if r := checkContentForPathWrites(target.Content, repoRoot); r.Block {
			return r
		}
	}

	// 6c. Bash command scan: detect shell redirects/write flags targeting repoRoot,
	//     catching pre-existing binaries invoked to write into the protected repo.
	if target.Command != "" {
		if r := checkBashCommandForWrites(target.Command, repoRoot); r.Block {
			return r
		}
	}

	// 7. Cross-repo write: target file is in a different git repo on a protected branch.
	if target.FilePath != "" && target.RepoRoot != "" && target.RepoRoot != repoRoot {
		for _, pattern := range cfg.ProtectedBranches {
			re, err := regexp.Compile("^" + pattern + "$")
			if err != nil {
				continue
			}
			if re.MatchString(target.Branch) {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("Target %q is in repo %q on protected branch %q. Protected branches: %s",
						target.FilePath, target.RepoRoot, target.Branch, strings.Join(cfg.ProtectedBranches, ", ")),
				}
			}
		}
	}

	return CheckResult{}
}
