package checks

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

// DetectLinter returns the linter config for a file based on its extension.
// Returns nil if no linter is configured.
func DetectLinter(filePath string, cfg config.Config) *config.LinterConfig {
	ext := filepath.Ext(filePath)
	if ext == "" {
		return nil
	}
	linter, ok := cfg.Linters[ext]
	if !ok {
		return nil
	}
	return &linter
}

// IsLintExcluded checks if a file path matches any lint exclusion pattern.
func IsLintExcluded(filePath string, exclusions []string) bool {
	for _, pattern := range exclusions {
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
		// Fallback: check if the trimmed pattern appears as a path component.
		trimmed := strings.Trim(pattern, "*/ ")
		if trimmed != "" && strings.Contains(filePath, trimmed) {
			return true
		}
	}
	return false
}

// RunLint runs the appropriate linter for a file and returns the result.
func RunLint(filePath string, cfg config.Config) CheckResult {
	if IsLintExcluded(filePath, cfg.LintExclusions) {
		return CheckResult{}
	}

	linter := DetectLinter(filePath, cfg)
	if linter == nil {
		return CheckResult{}
	}

	if _, err := exec.LookPath(linter.Cmd); err != nil {
		return CheckResult{
			Warning: fmt.Sprintf("Linter %q not found. Install it for automatic lint checks.", linter.Cmd),
		}
	}

	// Run formatter first if configured (non-fatal).
	if linter.Formatter != "" {
		parts := strings.Fields(linter.Formatter)
		if len(parts) > 0 {
			fmtArgs := append(parts[1:], filePath)
			_ = exec.Command(parts[0], fmtArgs...).Run()
		}
	}

	// Run linter.
	args := append(linter.Args, filePath)
	cmd := exec.Command(linter.Cmd, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return CheckResult{
				Warning: fmt.Sprintf("Lint issues in %s:\n%s", filePath, strings.TrimSpace(string(output))),
			}
		}
		// Non-exit errors (e.g., signal) — treat as warning too.
		return CheckResult{
			Warning: fmt.Sprintf("Linter error for %s: %v", filePath, err),
		}
	}

	return CheckResult{}
}
