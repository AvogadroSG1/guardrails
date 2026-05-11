package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AvogadroSG1/guardrails/internal/checks"
	"github.com/AvogadroSG1/guardrails/internal/config"
	"github.com/AvogadroSG1/guardrails/internal/router"
	"github.com/AvogadroSG1/guardrails/internal/state"
)

type HookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type HookOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName      string `json:"hookEventName"`
	PermissionDecision string `json:"permissionDecision"`
	AdditionalContext  string `json:"additionalContext,omitempty"`
}

// CheckResult is a type alias to checks.CheckResult so the rest of main.go
// can refer to it without the package prefix.
type CheckResult = checks.CheckResult

func main() {
	event := flag.String("event", "", "Hook event type: pre-tool-use or post-tool-use")
	checksFlag := flag.String("check", "", "Comma-separated list of checks to run")
	configPath := flag.String("config", "", "Path to config.json (optional)")
	flag.Parse()

	if *event == "" || *checksFlag == "" {
		fmt.Fprintln(os.Stderr, "Usage: guardrails --event <pre-tool-use|post-tool-use> --check <checks>")
		os.Exit(1)
	}

	// Load config
	cfgPath := *configPath
	if cfgPath == "" {
		home, _ := os.UserHomeDir()
		cfgPath = filepath.Join(home, ".claude", "hooks", "guardrails", "config.json")
	}
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Could not load config: %v (using defaults)\n", err)
		cfg = config.Default()
	}

	// Read stdin
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not read stdin: %v\n", err)
		os.Exit(1)
	}

	var hookInput HookInput
	if err := json.Unmarshal(input, &hookInput); err != nil {
		os.Exit(0)
	}

	// Resolve which checks to run
	requestedChecks := strings.Split(*checksFlag, ",")
	resolvedChecks := router.ResolveChecks(*event, hookInput.ToolName, requestedChecks)

	// Run checks
	var warnings []string

	for _, check := range resolvedChecks {
		result := runCheck(check, *event, hookInput, cfg)
		if result.Block {
			fmt.Fprintln(os.Stderr, result.Message)
			os.Exit(2)
		}
		if result.Warning != "" {
			warnings = append(warnings, result.Warning)
		}
	}

	if len(warnings) > 0 {
		output := HookOutput{
			HookSpecificOutput: &HookSpecificOutput{
				HookEventName:      "PreToolUse",
				PermissionDecision: "allow",
				AdditionalContext:  strings.Join(warnings, " "),
			},
		}
		json.NewEncoder(os.Stdout).Encode(output)
	}

	os.Exit(0)
}

func runCheck(name string, event string, input HookInput, cfg config.Config) CheckResult {
	switch name {
	case "secret-scan":
		return runSecretScan(event, input, cfg)
	case "safety-guard":
		return runSafetyGuard(input)
	case "guard-branch":
		return runGuardBranch(input, cfg)
	case "lint":
		return runLint(input, cfg)
	case "test-nudge":
		return runTestNudge(input, cfg)
	case "test-nudge-reset":
		return runTestNudgeReset(input, cfg)
	default:
		return CheckResult{}
	}
}

func runSecretScan(event string, input HookInput, cfg config.Config) CheckResult {
	if input.ToolName == "Bash" {
		var bash struct {
			Command string `json:"command"`
		}
		json.Unmarshal(input.ToolInput, &bash)
		return checks.ScanCommand(bash.Command, cfg.SecretScan)
	}
	// Write/Edit — scan file content
	var file struct {
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
		Path     string `json:"path"`
		NewText  string `json:"new_text"`
	}
	json.Unmarshal(input.ToolInput, &file)
	filePath := file.FilePath
	if filePath == "" {
		filePath = file.Path
	}
	content := file.Content
	if content == "" {
		content = file.NewText
	}
	if filePath != "" && content != "" {
		return checks.ScanFileContent(filePath, content, cfg.SecretScan)
	}
	return CheckResult{}
}

func runSafetyGuard(input HookInput) CheckResult {
	var bash struct {
		Command string `json:"command"`
	}
	json.Unmarshal(input.ToolInput, &bash)
	return checks.SafetyGuard(bash.Command)
}

func runGuardBranch(input HookInput, cfg config.Config) CheckResult {
	branch := gitCurrentBranch()
	repoRoot := gitRepoRoot()
	hasStagedChanges := gitHasStagedChanges()

	// Extract Write/Edit tool fields.
	var file struct {
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
		Path     string `json:"path"`
		NewText  string `json:"new_text"`
	}
	json.Unmarshal(input.ToolInput, &file)
	filePath := file.FilePath
	if filePath == "" {
		filePath = file.Path
	}
	content := file.Content
	if content == "" {
		content = file.NewText
	}

	// Extract Bash tool field.
	var bash struct {
		Command string `json:"command"`
	}
	json.Unmarshal(input.ToolInput, &bash)

	// Normalize filePath: resolve relative/dotdot components, then resolve
	// symlinks on the parent directory. The file itself may not exist yet (it is
	// being created), so EvalSymlinks runs on the parent rather than the full path.
	if filePath != "" {
		if abs, err := filepath.Abs(filePath); err == nil {
			abs = filepath.Clean(abs)
			if parent, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
				abs = filepath.Join(parent, filepath.Base(abs))
			}
			filePath = abs
		}
	}

	// Resolve git context for the target path.
	var targetBranch, targetRepoRoot string
	if filePath != "" {
		targetBranch = gitBranchForPath(filePath)
		targetRepoRoot = gitRepoRootForPath(filePath)
	}

	return checks.GuardBranch(branch, repoRoot, hasStagedChanges, cfg, checks.TargetInfo{
		FilePath: filePath,
		Branch:   targetBranch,
		RepoRoot: targetRepoRoot,
		Content:  content,
		Command:  bash.Command,
	})
}

func runLint(input HookInput, cfg config.Config) CheckResult {
	var file struct {
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
	}
	json.Unmarshal(input.ToolInput, &file)
	filePath := file.FilePath
	if filePath == "" {
		filePath = file.Path
	}
	if filePath == "" {
		return CheckResult{}
	}
	return checks.RunLint(filePath, cfg)
}

func runTestNudge(input HookInput, cfg config.Config) CheckResult {
	var file struct {
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
	}
	json.Unmarshal(input.ToolInput, &file)
	filePath := file.FilePath
	if filePath == "" {
		filePath = file.Path
	}
	if filePath == "" {
		return CheckResult{}
	}
	if !checks.IsSourceFile(filePath, cfg.TestNudge) {
		return CheckResult{}
	}
	counterPath := counterFilePath()
	counter, _ := state.Load(counterPath)
	counter.Increment(filePath)
	counter.Save(counterPath)
	return checks.TestNudgeCheck(counter, cfg.TestNudge)
}

func runTestNudgeReset(input HookInput, cfg config.Config) CheckResult {
	var bash struct {
		Command string `json:"command"`
	}
	json.Unmarshal(input.ToolInput, &bash)
	if checks.IsTestCommand(bash.Command, cfg.TestNudge) {
		counterPath := counterFilePath()
		counter, _ := state.Load(counterPath)
		counter.Reset()
		counter.Save(counterPath)
	}
	return CheckResult{}
}

// --- Git helper functions ---

func gitCurrentBranch() string {
	out, err := exec.Command("git", "symbolic-ref", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitRepoRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitHasStagedChanges() bool {
	err := exec.Command("git", "diff", "--cached", "--quiet").Run()
	return err != nil
}

func gitBranchForPath(path string) string {
	out, err := exec.Command("git", "-C", filepath.Dir(path), "symbolic-ref", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitRepoRootForPath(path string) string {
	out, err := exec.Command("git", "-C", filepath.Dir(path), "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func counterFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "hooks", "state", ".edit-counter")
}
