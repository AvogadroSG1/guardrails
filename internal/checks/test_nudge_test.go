package checks

import (
	"testing"

	"github.com/AvogadroSG1/guardrails/internal/config"
	"github.com/AvogadroSG1/guardrails/internal/state"
)

// containsCI is defined in safety_guard_test.go

func TestTestNudge_IsSourceFile(t *testing.T) {
	cfg := config.Default().TestNudge

	tests := []struct {
		path string
		want bool
	}{
		// Source files
		{"src/main.py", true},
		{"src/App.cs", true},
		{"src/index.ts", true},
		{"src/main.go", true},
		// Non-source extensions
		{"README.md", false},
		{"config.yaml", false},
		{"package.json", false},
		// Test files and directories
		{"tests/test_main.py", false},
		{"src/main_test.go", false},
		{"src/main.test.ts", false},
		{"test/fixtures.py", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := IsSourceFile(tc.path, cfg)
			if got != tc.want {
				t.Errorf("IsSourceFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestTestNudge_Escalation(t *testing.T) {
	cfg := config.Default().TestNudge

	tests := []struct {
		edits  int
		silent bool
		strong bool
	}{
		{0, true, false},
		{3, true, false},
		{4, true, false},
		{5, false, false},
		{7, false, false},
		{9, false, false},
		{10, false, true},
		{15, false, true},
	}

	for _, tc := range tests {
		counter := &state.EditCounter{SourceEdits: tc.edits}
		result := TestNudgeCheck(counter, cfg)

		isSilent := result.Warning == "" && result.Message == ""
		if isSilent != tc.silent {
			t.Errorf("edits=%d: silent = %v, want %v (Warning: %q)", tc.edits, isSilent, tc.silent, result.Warning)
		}

		if !tc.silent && tc.strong {
			if !containsCI(result.Warning, "SHOULD") {
				t.Errorf("edits=%d: strong nudge should contain 'SHOULD', got %q", tc.edits, result.Warning)
			}
		}
	}
}

func TestTestNudge_IsTestCommand(t *testing.T) {
	cfg := config.Default().TestNudge

	tests := []struct {
		command string
		want    bool
	}{
		{"pytest tests/ -v", true},
		{"dotnet test", true},
		{"npm test", true},
		{"npm run test", true},
		{"go test ./...", true},
		{"vitest run", true},
		{"git status", false},
		{"echo hello", false},
		{"ruff check main.py", false},
	}

	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			got := IsTestCommand(tc.command, cfg)
			if got != tc.want {
				t.Errorf("IsTestCommand(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}
