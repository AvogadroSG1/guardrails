package checks

import (
	"testing"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

func TestSecretScan_BlocksInlineAPIKey(t *testing.T) {
	cfg := config.Default().SecretScan

	tests := []struct {
		name    string
		command string
	}{
		{"export API_KEY", `export API_KEY=sk-abc123def456`},
		{"ATLASSIAN_CLIENT_SECRET", `ATLASSIAN_CLIENT_SECRET=somesecretvalue12345678`},
		{"bearer token in curl", `curl -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefg"`},
		{"AWS access key", `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`},
		{"GitHub PAT", `export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn`},
		{"private key header", `echo "-----BEGIN RSA PRIVATE KEY-----"`},
		{"DB_PASSWORD", `DB_PASSWORD=mysecretpassword123`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanCommand(tt.command, cfg)
			if !result.Block {
				t.Errorf("expected command to be blocked: %s", tt.command)
			}
		})
	}
}

func TestSecretScan_AllowsSafePatterns(t *testing.T) {
	cfg := config.Default().SecretScan

	tests := []struct {
		name    string
		command string
	}{
		{"os.getenv", `key = os.getenv("API_KEY")`},
		{"process.env", `const key = process.env.API_KEY`},
		{"Environment.GetEnvironmentVariable", `var secret = Environment.GetEnvironmentVariable("SECRET")`},
		{"Go template", `apiKey: {{ .ApiKey }}`},
		{"shell variable expansion", `export API_KEY=${API_KEY}`},
		{"config assignment", `config.secretName = "API_KEY"`},
		{"echo hello world", `echo "hello world"`},
		{"git status", `git status`},
		{"test key", `test-key-12345`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanCommand(tt.command, cfg)
			if result.Block {
				t.Errorf("expected command to be allowed: %s (message: %s)", tt.command, result.Message)
			}
		})
	}
}

func TestSecretScan_BlocksSecretEcho(t *testing.T) {
	cfg := config.Default().SecretScan

	tests := []struct {
		name      string
		command   string
		wantBlock bool
	}{
		{"echo $SECRET_KEY", `echo $SECRET_KEY`, true},
		{"echo $API_KEY", `echo $API_KEY`, true},
		{"printenv", `printenv`, true},
		{"printenv grep TOKEN", `printenv | grep TOKEN`, true},
		{"env grep SECRET", `env | grep SECRET`, true},
		{"echo hello", `echo "hello"`, false},
		{"echo HOME", `echo $HOME`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanCommand(tt.command, cfg)
			if result.Block != tt.wantBlock {
				t.Errorf("command %q: got Block=%v, want Block=%v (message: %s)", tt.command, result.Block, tt.wantBlock, result.Message)
			}
		})
	}
}

func TestSecretScan_FileContent(t *testing.T) {
	cfg := config.Default().SecretScan

	tests := []struct {
		name      string
		filePath  string
		content   string
		wantBlock bool
	}{
		{
			"hardcoded key in .py",
			"app.py",
			`API_KEY = "sk-abc123def456ghi789"`,
			true,
		},
		{
			"env reference in .py",
			"app.py",
			`API_KEY = os.getenv("API_KEY")`,
			false,
		},
		{
			".env file creation",
			".env",
			`API_KEY=somevalue`,
			true,
		},
		{
			".env.local creation",
			".env.local",
			`SECRET=somevalue`,
			true,
		},
		{
			"normal config yaml",
			"config.yaml",
			"database:\n  host: localhost\n  port: 5432\n",
			false,
		},
		{
			"private key in file",
			"key.pem",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanFileContent(tt.filePath, tt.content, cfg)
			if result.Block != tt.wantBlock {
				t.Errorf("file %q: got Block=%v, want Block=%v (message: %s)", tt.filePath, result.Block, tt.wantBlock, result.Message)
			}
		})
	}
}
