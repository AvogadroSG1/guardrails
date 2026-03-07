package router

import (
	"testing"
)

func TestResolveChecks_PreToolUse_Bash(t *testing.T) {
	checks := ResolveChecks("pre-tool-use", "Bash", []string{"secret-scan", "safety-guard"})
	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}
}

func TestResolveChecks_FiltersInvalid(t *testing.T) {
	checks := ResolveChecks("pre-tool-use", "Bash", []string{"secret-scan", "nonexistent"})
	if len(checks) != 1 {
		t.Errorf("expected 1 valid check, got %d", len(checks))
	}
}

func TestResolveChecks_EmptyInput(t *testing.T) {
	checks := ResolveChecks("pre-tool-use", "Bash", []string{})
	if len(checks) != 0 {
		t.Errorf("expected 0 checks, got %d", len(checks))
	}
}
