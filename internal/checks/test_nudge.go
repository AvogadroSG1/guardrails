package checks

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AvogadroSG1/guardrails/internal/config"
	"github.com/AvogadroSG1/guardrails/internal/state"
)

// IsSourceFile determines if a file should count toward the test nudge counter.
func IsSourceFile(filePath string, cfg config.TestNudgeConfig) bool {
	ext := filepath.Ext(filePath)
	if ext == "" {
		return false
	}

	// Check if extension is in the allowed source extensions.
	found := false
	for _, se := range cfg.SourceExtensions {
		if ext == se {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// Check directory parts for test directories.
	dir := filepath.Dir(filePath)
	parts := strings.Split(dir, string(filepath.Separator))
	for _, part := range parts {
		lower := strings.ToLower(part)
		if lower == "tests" || lower == "test" {
			return false
		}
	}

	// Check filename for test file patterns: *_test.ext, *.test.ext, test_*.ext
	base := filepath.Base(filePath)
	name := strings.TrimSuffix(base, ext)

	if strings.HasSuffix(name, "_test") {
		return false
	}
	if strings.HasSuffix(name, ".test") {
		return false
	}
	if strings.HasPrefix(name, "test_") {
		return false
	}

	return true
}

// TestNudgeCheck returns an escalating warning based on edit count.
func TestNudgeCheck(counter *state.EditCounter, cfg config.TestNudgeConfig) CheckResult {
	if counter.SourceEdits < cfg.WarnAfter {
		return CheckResult{}
	}

	if counter.SourceEdits >= cfg.StrongNudgeAfter {
		return CheckResult{
			Warning: fmt.Sprintf("You SHOULD run tests. %d source edits since last test run.", counter.SourceEdits),
		}
	}

	return CheckResult{
		Warning: fmt.Sprintf("Consider running tests: %d source edits since last test run.", counter.SourceEdits),
	}
}

// IsTestCommand detects if a bash command is running a test suite.
func IsTestCommand(command string, cfg config.TestNudgeConfig) bool {
	for _, tc := range cfg.TestCommands {
		if strings.Contains(command, tc) {
			return true
		}
	}
	return false
}
