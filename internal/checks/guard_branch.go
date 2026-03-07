package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

// GuardBranch checks if writes should be allowed based on branch and repo state.
func GuardBranch(branch string, repoRoot string, hasStagedChanges bool, cfg config.Config) CheckResult {
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

	return CheckResult{}
}
