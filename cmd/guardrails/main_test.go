package main

import (
	"encoding/json"
	"testing"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

func TestRunCheck_SecretScan_BlocksCommand(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "export API_KEY=sk-abc123456789"}`),
	}
	result := runCheck("secret-scan", "pre-tool-use", input, cfg)
	if !result.Block {
		t.Error("expected secret scan to block inline API key")
	}
}

func TestRunCheck_SecretScan_AllowsSafe(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "git status"}`),
	}
	result := runCheck("secret-scan", "pre-tool-use", input, cfg)
	if result.Block {
		t.Error("expected git status to be allowed")
	}
}

func TestRunCheck_SafetyGuard_BlocksRmRf(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "rm -rf /tmp/foo"}`),
	}
	result := runCheck("safety-guard", "pre-tool-use", input, cfg)
	if !result.Block {
		t.Error("expected safety guard to block rm -rf")
	}
}

func TestRunCheck_SecretScan_BlocksFileContent(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Write",
		ToolInput: json.RawMessage(`{"file_path": "config.py", "content": "api_key = \"sk-abc123456789abcdef\""}`),
	}
	result := runCheck("secret-scan", "pre-tool-use", input, cfg)
	if !result.Block {
		t.Error("expected secret scan to block hardcoded key in file content")
	}
}

func TestRunCheck_Unknown_NoOp(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "ls"}`),
	}
	result := runCheck("nonexistent", "pre-tool-use", input, cfg)
	if result.Block {
		t.Error("unknown check should not block")
	}
}

func TestRunCheck_SafetyGuard_AllowsSafe(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "git status"}`),
	}
	result := runCheck("safety-guard", "pre-tool-use", input, cfg)
	if result.Block {
		t.Error("expected git status to be allowed by safety guard")
	}
}

func TestRunCheck_SecretScan_EditToolUsesPath(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Edit",
		ToolInput: json.RawMessage(`{"path": "app.py", "new_text": "token = \"ghp_abcdefghijklmnopqrstuvwxyz1234567890\""}`),
	}
	result := runCheck("secret-scan", "pre-tool-use", input, cfg)
	if !result.Block {
		t.Error("expected secret scan to block GitHub token in Edit tool")
	}
}

func TestRunCheck_SafetyGuard_BlocksSudo(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "sudo rm foo"}`),
	}
	result := runCheck("safety-guard", "pre-tool-use", input, cfg)
	if !result.Block {
		t.Error("expected safety guard to block sudo")
	}
}

func TestRunCheck_SafetyGuard_WarnsOnGitPush(t *testing.T) {
	cfg := config.Default()
	input := HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "git push origin feature-branch"}`),
	}
	result := runCheck("safety-guard", "pre-tool-use", input, cfg)
	if result.Block {
		t.Error("expected git push to feature branch to be allowed")
	}
	if result.Warning == "" {
		t.Error("expected git push to produce a warning")
	}
}
