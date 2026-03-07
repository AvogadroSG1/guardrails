package checks

import (
	"testing"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

func TestLint_DetectsExtension(t *testing.T) {
	cfg := config.Default()

	tests := []struct {
		name     string
		filePath string
		wantCmd  string
		wantNil  bool
	}{
		{"python", "src/main.py", "ruff", false},
		{"go", "src/main.go", "golangci-lint", false},
		{"markdown", "README.md", "markdownlint", false},
		{"typescript", "src/index.ts", "eslint", false},
		{"csharp", "src/Program.cs", "dotnet", false},
		{"javascript", "src/index.js", "eslint", false},
		{"tsx not configured", "src/App.tsx", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectLinter(tt.filePath, cfg)
			if tt.wantNil {
				if result != nil {
					t.Errorf("DetectLinter(%q) = %v, want nil", tt.filePath, result)
				}
				return
			}
			if result == nil {
				t.Fatalf("DetectLinter(%q) = nil, want cmd %q", tt.filePath, tt.wantCmd)
			}
			if result.Cmd != tt.wantCmd {
				t.Errorf("DetectLinter(%q).Cmd = %q, want %q", tt.filePath, result.Cmd, tt.wantCmd)
			}
		})
	}
}

func TestLint_ExcludedPaths(t *testing.T) {
	cfg := config.Default()

	tests := []struct {
		name     string
		filePath string
		excluded bool
	}{
		{"obsidian notes", "/Users/poconnor/ObsidianNotes/Work/notes.md", true},
		{"docs folder", "/Users/poconnor/code/docs/readme.md", true},
		{"claude config", "/Users/poconnor/.claude/hooks/config.json", true},
		{"source code", "/Users/poconnor/code/src/main.py", false},
		{"plans folder", "/Users/poconnor/code/plans/plan.md", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLintExcluded(tt.filePath, cfg.LintExclusions)
			if result != tt.excluded {
				t.Errorf("IsLintExcluded(%q) = %v, want %v", tt.filePath, result, tt.excluded)
			}
		})
	}
}
