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

// contentWritePatterns detects non-redirect write operations in file content.
// Shell redirects are handled separately in checkContentForPathWrites to
// correctly prioritise them over read-only suppression.
// The open() pattern requires an explicit write/append/create/update mode
// (w, a, x, or + in any position) to avoid false-positives on 'r', 'rb', etc.
var contentWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`open\s*\(.*,\s*['"][^'"]*[wax+]`),  // Python open in write/append/create/update mode
	regexp.MustCompile(`fs\.(writeFile|appendFile)\s*\(`),   // Node.js
	regexp.MustCompile(`\b(cp|mv|rsync)\s+`),                // copy/move
}

// contentReadOnlyPatterns matches operations that only read; used to suppress
// false positives when no shell redirect is present.
var contentReadOnlyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bcat\s+`),
	regexp.MustCompile(`open\s*\(.*,\s*['"]r['"]\s*\)`), // Python open(..., 'r')
}

// shellRedirectRE matches shell redirect operators (> or >>) in content lines.
// Boundary checks in the consuming code exclude >=, =>, and -> false positives.
var shellRedirectRE = regexp.MustCompile(`>{1,2}`)

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
// repoRoot. Uses repoRoot+"/" (repoPrefix) so that sibling directories whose
// path contains repoRoot as a substring are not falsely matched.
// Shell redirects are checked first and override read-only suppression so that
// lines like "cat /repo/in > /repo/out" are correctly caught.
func checkContentForPathWrites(content, repoRoot string) CheckResult {
	if repoRoot == "" {
		return CheckResult{}
	}
	sep := string(os.PathSeparator)
	repoPrefix := repoRoot + sep // require path boundary to avoid matching siblings

	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, repoPrefix) {
			continue
		}

		// Shell redirect takes priority: check whether repoPrefix appears after
		// any > or >> operator in this line. This must run before read-only
		// suppression so "cat /repo/in > /repo/out" is correctly blocked.
		// Boundary checks skip >=, =>, -> which are not shell redirects.
		for _, loc := range shellRedirectRE.FindAllStringIndex(line, -1) {
			afterPos := loc[1]
			// >= is a comparison operator, not a redirect.
			if afterPos < len(line) && line[afterPos] == '=' {
				continue
			}
			// => (fat arrow) and -> (pointer) are not redirects.
			if loc[0] > 0 && (line[loc[0]-1] == '=' || line[loc[0]-1] == '-') {
				continue
			}
			if strings.Contains(line[afterPos:], repoPrefix) {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("File content writes to protected repo %q: %q", repoRoot, truncate(line, 120)),
				}
			}
		}

		// Skip lines that are purely read-only (no redirect matched above).
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

		// Other write patterns: Python open in write mode, Node.js, cp/mv.
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

		// Shell redirect: the portion before this occurrence ends with > or >>.
		// HasSuffix naturally excludes >= (which ends with =, not >) and =>
		// (which also ends with > preceded by = — but trimmed ends with > so we
		// must also check the character before the >).
		trimmed := strings.TrimRight(before, " \t")
		if strings.HasSuffix(trimmed, ">") || strings.HasSuffix(trimmed, ">>") {
			// Exclude => and ->: check the character immediately before the > (or >>).
			isDoubleAngle := strings.HasSuffix(trimmed, ">>")
			charBeforeArrow := len(trimmed) - 1 // index of trailing >
			if isDoubleAngle {
				charBeforeArrow = len(trimmed) - 2 // index of first > in >>
			}
			charBefore := charBeforeArrow - 1 // character preceding the arrow
			if charBefore >= 0 && (trimmed[charBefore] == '=' || trimmed[charBefore] == '-') {
				// => or -> (or =>> / ->>) — not a shell redirect.
			} else {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
				}
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
