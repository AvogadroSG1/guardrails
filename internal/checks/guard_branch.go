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
// when written to temp or non-git paths. Covers commits, pushes, and all
// operations that rewrite history, apply commits, or manipulate branches.
var tempAlwaysBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)git\s+commit\b`),
	regexp.MustCompile(`(?i)git\s+push\b`),
	regexp.MustCompile(`(?i)git\s+reset\b`),
	regexp.MustCompile(`(?i)git\s+merge\b`),
	regexp.MustCompile(`(?i)git\s+rebase\b`),
	regexp.MustCompile(`(?i)git\s+cherry-pick\b`),
	regexp.MustCompile(`(?i)git\s+am\b`),
	regexp.MustCompile(`(?i)git\s+stash\b`),
}

var tempCheckoutPattern = regexp.MustCompile(`(?i)git\s+(checkout|switch)\s+`)

// cpMvRsyncRE matches cp/mv/rsync commands for destination-aware write detection.
var cpMvRsyncRE = regexp.MustCompile(`\b(cp|mv|rsync)\b`)

// shellRedirectRE matches any > or >> operator. The consuming code uses
// isShellRedirect to exclude false positives from >=, =>, and -> operators.
// Intentionally broad to catch no-space redirects like "echo>/path".
var shellRedirectRE = regexp.MustCompile(`(>{1,2})`)

// writeOpAtEndRE matches write operators anchored to the end of the "before"
// portion of a Bash command (the text preceding a repoRoot path occurrence).
// Covers tee (piped or direct, with optional flags like -a), common CLI write
// flags in both space-separated (--output /path) and equals-separated
// (--output=/path) forms, and the short -o flag.
var writeOpAtEndRE = regexp.MustCompile(`(?:(?:^|\|)\s*tee(?:\s+-\w+)*|--output=?|--file=?|--target=?|--write(?:-to)?=?|(?:^|\s)-o=?)$`)

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

// isObsidianNotesRepo reports whether root is an ObsidianNotes vault by checking
// exact path components. strings.Contains would falsely match repos whose name
// contains "ObsidianNotes" as a substring (e.g. "myObsidianNotesPlugin").
func isObsidianNotesRepo(root string) bool {
	for _, component := range strings.Split(root, string(os.PathSeparator)) {
		if component == "ObsidianNotes" {
			return true
		}
	}
	return false
}

// repoIsExcluded reports whether root is exempt from branch protection under
// the active config. Uses exact match or separator-bounded prefix to avoid
// matching sibling directories (e.g. excl "/my-repo" must not exempt "/my-repo2").
func repoIsExcluded(root string, cfg config.Config) bool {
	sep := string(os.PathSeparator)
	for _, excl := range cfg.RepoExclusions {
		if root == excl || strings.HasPrefix(root, excl+sep) {
			return true
		}
	}
	return isObsidianNotesRepo(root)
}

// cpMvTargetsRepo reports whether a cp/mv/rsync command line writes INTO the
// protected repo. The destination is the last path-like token (starting with /).
// This prevents false positives when repoRoot is the source, not the destination.
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

// isShellRedirect reports whether the > or >> operator at [opStart, afterEnd)
// in line is an actual shell redirect rather than a >=, =>, or -> operator.
func isShellRedirect(line string, opStart, afterEnd int) bool {
	if opStart > 0 && (line[opStart-1] == '=' || line[opStart-1] == '-') {
		return false // => or ->
	}
	if afterEnd < len(line) && line[afterEnd] == '=' {
		return false // >=
	}
	return true
}

// extractRedirectTarget extracts the path token immediately following a shell
// redirect operator (> or >>). Skips leading whitespace and optional quotes.
// Returns the extracted path or empty string if no path token is found.
func extractRedirectTarget(line string, afterRedirect int) string {
	rest := line[afterRedirect:]
	// Skip leading whitespace
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) {
		return ""
	}
	
	// Check for optional quotes
	quote := byte(0)
	if rest[i] == '"' || rest[i] == '\'' {
		quote = rest[i]
		i++
	}
	
	// Extract the path token
	start := i
	if quote != 0 {
		// Find closing quote
		for i < len(rest) && rest[i] != quote {
			i++
		}
	} else {
		// Find end of token (whitespace or shell metacharacter)
		for i < len(rest) && rest[i] != ' ' && rest[i] != '\t' && rest[i] != ';' && rest[i] != '|' && rest[i] != '&' {
			i++
		}
	}
	
	return rest[start:i]
}

// checkTempOrNonGitContent scans file content for git manipulation commands.
// Tier-1: always block commit/push/reset/merge/rebase/cherry-pick/am/stash.
// Tier-2: block checkout/switch targeting a protected branch from cfg.
// Checkout/switch flags covered: -b, -B, -c, -C, -t, --create, --force-create,
// --track, --orphan. Protected-branch regexes are compiled once before the scan.
func checkTempOrNonGitContent(content string, cfg config.Config) CheckResult {
	// Pre-compile protected-branch checkout/switch patterns once for all lines.
	var checkoutREs []*regexp.Regexp
	for _, pattern := range cfg.ProtectedBranches {
		re, err := regexp.Compile(`(?i)git\s+(checkout|switch)\s+(-[bBcCt]\s+|--(?:create|force-create|track|orphan)\s+)?` + pattern + `(?:\s|$)`)
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
// repoRoot. Uses repoRoot+"/" (repoPrefix) to avoid false-positives from sibling
// directories. Shell redirects use a broad regex that catches both spaced
// ("echo > /path") and no-space ("echo>/path") forms; isShellRedirect excludes
// >=, =>, and -> operators. Python/Node/tee write patterns are destination-aware:
// they require repoPrefix to appear in the write-target path argument, not just
// anywhere on the line. cp/mv/rsync detection is destination-aware via
// cpMvTargetsRepo.
func checkContentForPathWrites(content, repoRoot string) CheckResult {
	if repoRoot == "" {
		return CheckResult{}
	}
	sep := string(os.PathSeparator)
	repoPrefix := repoRoot + sep

	// Build destination-aware write patterns specific to this repoPrefix.
	// These require repoPrefix to be the path being written TO, eliminating
	// false positives when repoPrefix appears only as a read argument.
	qp := regexp.QuoteMeta(repoPrefix)
	repoPrefixWritePatterns := []*regexp.Regexp{
		// Python open() with repoPrefix as the path arg in a write-capable mode
		// (w, a, x, or any mode containing +). Requires explicit mode argument.
		regexp.MustCompile(`open\s*\(\s*['"]` + qp + `[^'"]*['"]\s*,\s*['"][^'"]*[wax+]`),
		// Node.js fs.writeFile / fs.appendFile with repoPrefix as the path arg.
		regexp.MustCompile(`fs\.(writeFile|appendFile)\s*\(\s*['"]` + qp),
		// tee command (with optional flags like -a) writing directly to repoPrefix.
		regexp.MustCompile(`\btee(?:\s+-\w+)*\s+['"]?` + qp),
	}

	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, repoPrefix) {
			continue
		}

		// Shell redirect: broad regex catches both spaced and no-space forms.
		// isShellRedirect excludes >=, =>, and -> false positives.
		// extractRedirectTarget parses the actual redirect target token to avoid
		// false positives when repoPrefix appears elsewhere on the line.
		for _, loc := range shellRedirectRE.FindAllStringSubmatchIndex(line, -1) {
			opStart := loc[2]  // position of first >
			afterEnd := loc[3] // position after > or >>
			if !isShellRedirect(line, opStart, afterEnd) {
				continue
			}
			target := extractRedirectTarget(line, afterEnd)
			if strings.HasPrefix(target, repoPrefix) || target == repoRoot {
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

		// Python open / Node.js / tee: destination-aware patterns require repoPrefix
		// to be the path argument of the write call (not just anywhere on the line).
		for _, re := range repoPrefixWritePatterns {
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

// checkBashCommandForWrites detects shell redirects, write-flag patterns, and
// cp/mv/rsync commands in a Bash command that target the protected repo path.
// Uses repoRoot+"/" (repoPrefix) to avoid false-positives from sibling directories.
// Scans ALL occurrences of repoPrefix so "cat /repo/in > /repo/out" is caught at
// the second occurrence. Quoted redirect targets (e.g. > "/repo/file") are handled
// by stripping trailing quotes before the > suffix check. Write flags in equals
// form (--output=/path) are handled by using the quote-stripped portion for the
// writeOpAtEndRE match.
func checkBashCommandForWrites(command, repoRoot string) CheckResult {
	if repoRoot == "" {
		return CheckResult{}
	}
	sep := string(os.PathSeparator)
	repoPrefix := repoRoot + sep
	if !strings.Contains(command, repoPrefix) {
		return CheckResult{}
	}

	// cp/mv/rsync: destination-aware check on the full command string.
	if cpMvRsyncRE.MatchString(command) && cpMvTargetsRepo(command, repoPrefix) {
		return CheckResult{
			Block:   true,
			Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
		}
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
		// Strip trailing quotes and whitespace together. For "cmd > \"/repo/f\"",
		// trimmed ends with \" so stripping only spaces leaves the " in place;
		// stripping both removes the " and then the space, exposing the >.
		trimmedOp := strings.TrimRight(trimmed, " \t\"'")

		// Shell redirect: trimmedOp ends with > or >>. Exclude =>, ->, >= by
		// inspecting the character immediately before the > operator.
		if strings.HasSuffix(trimmedOp, ">") || strings.HasSuffix(trimmedOp, ">>") {
			isDouble := strings.HasSuffix(trimmedOp, ">>")
			opStart := len(trimmedOp) - 1
			if isDouble {
				opStart = len(trimmedOp) - 2
			}
			charBefore := opStart - 1
			if charBefore < 0 || (trimmedOp[charBefore] != '=' && trimmedOp[charBefore] != '-') {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("Bash command writes to protected repo %q: blocked to prevent indirect branch bypass.", repoRoot),
				}
			}
		}

		// Write operators (tee, --output=, etc.): use trimmedOp so that equals-form
		// flags (e.g. --output="/repo/f" → trimmedOp ends with --output=) are matched.
		if writeOpAtEndRE.MatchString(trimmedOp) {
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

	// 6c. Bash command scan: detect shell redirects/write flags/cp/mv targeting
	//     repoRoot, catching pre-existing binaries invoked to write into the repo.
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

	// 2. Check repo exclusions from config. Uses separator-bounded prefix to avoid
	//    matching sibling directories (excl "/my-repo" must not exempt "/my-repo2").
	sep := string(os.PathSeparator)
	for _, excl := range cfg.RepoExclusions {
		if repoRoot == excl || strings.HasPrefix(repoRoot, excl+sep) {
			return CheckResult{}
		}
	}

	// 3. Default exclusion: ObsidianNotes repos are always allowed.
	if isObsidianNotesRepo(repoRoot) {
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
