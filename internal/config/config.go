package config

import (
	"encoding/json"
	"errors"
	"os"
)

type LinterConfig struct {
	Cmd       string   `json:"cmd"`
	Args      []string `json:"args"`
	Formatter string   `json:"formatter,omitempty"`
}

type TestNudgeConfig struct {
	WarnAfter        int      `json:"warnAfter"`
	StrongNudgeAfter int      `json:"strongNudgeAfter"`
	SourceExtensions []string `json:"sourceExtensions"`
	TestCommands     []string `json:"testCommands"`
}

type SecretScanConfig struct {
	Patterns          []string `json:"patterns"`
	AllowPatterns     []string `json:"allowPatterns"`
	BlockFilePatterns []string `json:"blockFilePatterns"`
}

type Config struct {
	ProtectedBranches []string                `json:"protectedBranches"`
	RepoExclusions    []string                `json:"repoExclusions"`
	TestNudge         TestNudgeConfig         `json:"testNudge"`
	Linters           map[string]LinterConfig `json:"linters"`
	SecretScan        SecretScanConfig        `json:"secretScan"`
	LintExclusions    []string                `json:"lintExclusions"`
}

func Default() Config {
	return Config{
		ProtectedBranches: []string{"main", "master", "develop", "release/.*", "production"},
		RepoExclusions:    []string{},
		TestNudge: TestNudgeConfig{
			WarnAfter:        5,
			StrongNudgeAfter: 10,
			SourceExtensions: []string{".py", ".cs", ".ts", ".js", ".go", ".jsx", ".tsx"},
			TestCommands:     []string{"pytest", "dotnet test", "npm test", "npm run test", "go test", "vitest"},
		},
		Linters: map[string]LinterConfig{
			".py": {Cmd: "ruff", Args: []string{"check", "--fix"}, Formatter: "ruff format"},
			".cs": {Cmd: "dotnet", Args: []string{"format", "--verify-no-changes"}},
			".ts": {Cmd: "eslint", Args: []string{}},
			".js": {Cmd: "eslint", Args: []string{}},
			".md": {Cmd: "markdownlint", Args: []string{}},
			".go": {Cmd: "golangci-lint", Args: []string{"run"}},
		},
		SecretScan: SecretScanConfig{
			Patterns: []string{
				`(?i)(api[_-]?key|secret|token|password|credential)\s*[=:]\s*['"]?[A-Za-z0-9+/=_-]{8,}`,
				`(?i)AKIA[0-9A-Z]{16}`,
				`(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`,
				`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`,
				`(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}`,
			},
			AllowPatterns: []string{
				`\$\{.*\}`,
				`os\.getenv\(`,
				`os\.environ\[`,
				`process\.env\.`,
				`Environment\.GetEnvironmentVariable`,
				`\{\{\s*\.\w+\s*\}\}`,
			},
			BlockFilePatterns: []string{
				`\.env$`,
				`\.env\.local$`,
				`\.env\.production$`,
			},
		},
		LintExclusions: []string{
			"*/ObsidianNotes/*",
			"*/docs/*",
			"*/plans/*",
			"*/.claude/*",
		},
	}
}

func LoadFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, err
	}

	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
