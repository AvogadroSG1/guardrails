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

// contentWritePatterns detects non-redirect, non-cp/mv write operations in
// file content. Shell redirects and cp/mv/rsync are handled separately with
// destination-aware logic to avoid false positives when repoRoot is the source.
var contentWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`open\s*\(.*,\s*['"][^'"]*[wax+]`),  // Python open in write/append/create/update mode
	regexp.MustCompile(`fs\.(writeFile|appendFile)\s*\(`),   // Node.js
}

// cpMvRsyncRE matches cp/mv/rsync commands for destination-aware write detection.
var cpMvRsyncRE = regexp.MustCompile(`\b(cp|mv|rsync)\b`)

// contentReadOnlyPatterns matches operations that only read; used to suppress
// false positives when no shell redirect is present.
var contentReadOnlyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bcat\s+`),
	regexp.MustCompile(`open\s*\(.*,\s*['"]r['"]\s*\)`), // Python open(..., 'r')
}

// shellRedirectRE matches shell redirect operators (> or >>) only when preceded
// by whitespace, a shell metachar (;|&), digit (file descriptor), or
// start-of-line. This avoids false positives from >=, =>, and -> operators.
// The > or >> is in capture group 1; use FindAllStringSubmatchIndex.
var shellRedirectRE = regexp.MustCompile(`(?:^|[\s;|&\d])(>{1,2})`)

// writeOpAtEndRE matches write operators that must appear immediately before the
// target path in a Bash command (i.e. anchored to the end of the before-portion).
// Covers tee, common CLI write flags, and the short -o flag.
var writeOpAtEndRE = regexp.MustCompile(`(?:\|\s*tee|--output|--file|--target|--write(?:-to)?|\s-o)$`)

func isTempPath(path string) bool {
	for _, dir := range knownTempDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	// os.TempDir() may return a path without a trailing separator (e.g. "/tmp"),
	// which would cause "/tmpfile" to falsely match. Always append the separator.
	if t := os.TempDir(); t != "" {
		if !strings.HasSuffix(t, string(os.PathSeparator)) {
			t += string(os.PathSeparator)
		}
		if strings.HasPrefix(path, t) {
			return true
		}
	}
	return false
}

// repoIsExcluded reports whether root is exempt from branch protection under
// the active config (covers both RepoExclusions and the ObsidianNotes default).
func repoIsExcluded(root string, cfg config.Config) bool {
	for _, excl := range cfg.RepoExclusions {
		if strings.HasPrefix(root, excl) {
			return true
		}
	}
	return strings.Contains(root, "ObsidianNotes")
}

// cpMvTargetsRepo reports whether a cp/mv/rsync command line writes INTO the
// protected repo. The destination is identified as the last path-like token
// (starting with /) in the line; the check only fires when that token is under
// repoPrefix, preventing false positives when repoRoot is the source argument.
func cpMvTargetsRepo(line, repoPrefix string) bool {
	tokens := strings.Fields(line)
	for i := len(tokens) - 1; i >= 0; i-- {
		t := strings.Trim(tokens[i], `"'`)
		if strings.HasPrefix(t, "/") {
			return strings.HasPrefix(t, repoPrefix)
		}
	}
	return false
}

// checkTempOrNonGitContent scans file content for git manipulation commands.
// Tier-1: always block commit/push/reset. Tier-2: block checkout/switch only
// when targeting a protected branch from cfg.
// Protected-branch checkout regexes are compiled once before the line scan.
func checkTempOrNonGitContent(content string, cfg config.Config) CheckResult {
	// Pre-compile protected-branch checkout/switch patterns once for all lines.
	var checkoutREs []*regexp.Regexp
	for _, pattern := range cfg.ProtectedBranches {
		re, err := regexp.Compile(`(?i)git\s+(checkout|switch)\s+(-b\s+)?` + pattern + `\b`)
		if err != nil {
			continue
		}
		checkoutREs = append(checkoutREs, re)
	}

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
			for _, re := range checkoutREs {
				if re.MatchString(line) {
					return CheckResult{
						Block:   true,
						Message: fmt.Sprintf("Script in temp/non-git path targets protected branch: %q", truncate(line, 120)),
					}
				}
			}
		}
	}
	return CheckResult{}
}

// checkContentForPathWrites scans file content for write operations targeting
// repoRoot. Uses repoRoot+"/" (repoPrefix) so that sibling directories whose
// path contains repoRoot as a substring are not falsely matched.
// Shell redirects are checked first and override read-only suppression so that
// lines like "cat /repo/in > /repo/out" are correctly caught.
// cp/mv/rsync only trigger when repoRoot is the destination, not the source.
func checkContentForPathWrites(content, repoRoot string) CheckResult {
	if repoRoot == "" {
		return CheckResult{}
	}
	sep := string(os.PathSeparator)
	repoPrefix := repoRoot + sep

	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, repoPrefix) {
			continue
		}

		// Shell redirect takes priority: check whether repoPrefix appears after
		// any > or >> operator in this line. shellRedirectRE requires the > to be
		// preceded by whitespace/metachar/digit, which excludes =>, -> operators.
		// We additionally skip >= (> followed by =) in the loop below.
		for _, loc := range shellRedirectRE.FindAllStringSubmatchIndex(line, -1) {
			// loc[2]:loc[3] is capture group 1 (the > or >>).
			afterPos := loc[3]
			// Skip >= (comparison operator): > followed immediately by =.
			if afterPos < len(line) && line[afterPos] == '=' {
				continue
			}
			if strings.Contains(line[afterPos:], repoPrefix) {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("File content writes to protected repo %q: %q", repoRoot, truncate(line, 120)),
				}
			}
		}

		// cp/mv/rsync: only block when repoPrefix is the destination (last path token).
		if cpMvRsyncRE.MatchString(line) {
			if cpMvTargetsRepo(line, repoPrefix) {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("File content writes to protected repo %q: %q", repoRoot, truncate(line, 120)),
				}
			}
		}

		// Skip lines that are purely read-only (no redirect or cp/mv matched above).
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

		// Remaining write patterns: Python open in write mode, Node.js.
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
// Bash command that target the protected repo path. Uses repoRoot+"/" (repoPrefix)
// to avoid false-positives from sibling directories. Scans ALL occurrences so
// "cat /repo/in > /repo/out" is caught at the second occurrence.
//
// Write flags (--output, -o, etc.) are only flagged when they appear immediately
// before the repoRoot occurrence (i.e. the flag is the last token in the
// before-portion), preventing false positives like:
// "tool --output /tmp/out /repo/input" where the flag targets /tmp/out.
func checkBashCommandForWrites(command, repoRoot string) CheckResult {
	if repoRoot == "" {
		return CheckResult{}
	}
	sep := string(os.PathSeparator)
	repoPrefix := repoRoot + sep
	if !strings.Contains(command, repoPrefix) {
		return CheckResult{}
	}

	offset := 0
	for {
		idx := strings.Index(command[offset:], repoPrefix)
		if idx == -1 {
			break
		}
		absIdx := offset + idx
		before := command[:absIdx]
		trimmed := strings.TrimRight(before, " \t")

		// Shell redirect: the portion before this occurrence ends with > or >>.
		// Exclude => and ->: check the character immediately before the arrow.
		if strings.HasSuffix(trimmed, ">") || strings.HasSuffix(trimmed, ">>") {
			isDoubleArrow := strings.HasSuffix(trimmed, ">>")
			charBeforeArrow := len(trimmed) - 1 // index of trailing >
			if isDoubleArrow {
				charBeforeArrow = len(trimmed) - 2 // index of first > in >>
			}
			charBefore := charBeforeArrow - 1
			if charBefore < 0 || (trimmed[charBefore] != '=' && trimmed[charBefore] != '-') {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
				}
			}
		}

		// Write operators (tee, --output, etc.) must appear immediately before
		// repoRoot — i.e. the write op is the last meaningful token in before.
		if writeOpAtEndRE.MatchString(trimmed) {
			return CheckResult{
				Block:   true,
				Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
			}
		}

		offset = absIdx + len(repoPrefix)
	}
	return CheckResult{}
}

// GuardBranch checks if writes should be allowed based on branch, repo state,
// and target file/command context.
func GuardBranch(branch string, repoRoot string, hasStagedChanges bool, cfg config.Config, target TargetInfo) CheckResult {
	// Target-based bypass checks run unconditionally — even when CWD has no git
	// repo (branch == "") — because a script or Bash command can still write into
	// a protected repo from outside any git working tree.

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

	// 7. Cross-repo write: target file is in a different git repo on a protected
	//    branch. Honors RepoExclusions and ObsidianNotes for the target repo.
	if target.FilePath != "" && target.RepoRoot != "" && target.RepoRoot != repoRoot &&
		!repoIsExcluded(target.RepoRoot, cfg) {
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

	// 1. Empty branch means detached HEAD or CWD is outside any git repo — allow
	//    CWD-based writes (target-based checks above have already run).
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

	return CheckResult{}
}
