package checks

import (
	"strings"
	"testing"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

func TestGuardBranch_ProtectedBranch(t *testing.T) {
	cfg := config.Default()

	tests := []struct {
		name     string
		branch   string
		repoRoot string
		want     bool // true = block
	}{
		{"main on code project", "main", "/Users/test/code/myproject", true},
		{"master on code project", "master", "/Users/test/code/myproject", true},
		{"develop on code project", "develop", "/Users/test/code/myproject", true},
		{"release/v1.0 on code project", "release/v1.0", "/Users/test/code/myproject", true},
		{"production on code project", "production", "/Users/test/code/myproject", true},
		{"feature/my-thing on code project", "feature/my-thing", "/Users/test/code/myproject", false},
		{"bugfix/fix-crash on code project", "bugfix/fix-crash", "/Users/test/code/myproject", false},
		{"main on ObsidianNotes", "main", "/Users/test/ObsidianNotes/Work", false},
		{"empty branch on code project", "", "/Users/test/code/myproject", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GuardBranch(tt.branch, tt.repoRoot, false, cfg)
			if result.Block != tt.want {
				t.Errorf("GuardBranch(%q, %q) block = %v, want %v; message = %q",
					tt.branch, tt.repoRoot, result.Block, tt.want, result.Message)
			}
		})
	}
}

func TestGuardBranch_StagedChanges(t *testing.T) {
	cfg := config.Default()

	result := GuardBranch("feature/foo", "/Users/test/code/myproject", true, cfg)
	if !result.Block {
		t.Fatal("expected block when staged changes exist")
	}
	if !strings.Contains(result.Message, "staged") {
		t.Errorf("message should contain 'staged', got: %q", result.Message)
	}
}

func TestGuardBranch_CustomExclusions(t *testing.T) {
	cfg := config.Default()
	cfg.RepoExclusions = append(cfg.RepoExclusions, "/Users/test/my-content-repo")

	result := GuardBranch("main", "/Users/test/my-content-repo", false, cfg)
	if result.Block {
		t.Errorf("expected allow for custom-excluded repo, got block: %q", result.Message)
	}
}
