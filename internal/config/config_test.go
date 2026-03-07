package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_DefaultValues(t *testing.T) {
	cfg := Default()

	if len(cfg.ProtectedBranches) == 0 {
		t.Fatal("expected default protected branches")
	}
	if cfg.TestNudge.WarnAfter != 5 {
		t.Errorf("expected WarnAfter=5, got %d", cfg.TestNudge.WarnAfter)
	}
	if cfg.TestNudge.StrongNudgeAfter != 10 {
		t.Errorf("expected StrongNudgeAfter=10, got %d", cfg.TestNudge.StrongNudgeAfter)
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	data := []byte(`{
		"protectedBranches": ["main", "production"],
		"testNudge": {
			"warnAfter": 3,
			"strongNudgeAfter": 7,
			"sourceExtensions": [".py", ".go"],
			"testCommands": ["pytest", "go test"]
		}
	}`)
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ProtectedBranches) != 2 {
		t.Errorf("expected 2 branches, got %d", len(cfg.ProtectedBranches))
	}
	if cfg.TestNudge.WarnAfter != 3 {
		t.Errorf("expected WarnAfter=3, got %d", cfg.TestNudge.WarnAfter)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{invalid`), 0644)

	_, err := LoadFromFile(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadConfig_MissingFile_ReturnsDefault(t *testing.T) {
	cfg, err := LoadFromFile("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("missing file should return default, got error: %v", err)
	}
	if cfg.TestNudge.WarnAfter != 5 {
		t.Error("expected default config when file missing")
	}
}
