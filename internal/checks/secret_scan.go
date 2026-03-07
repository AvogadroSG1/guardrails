package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AvogadroSG1/guardrails/internal/config"
)

// CheckResult represents the outcome of a guardrail check.
// Used by all check modules in this package.
type CheckResult struct {
	Block   bool
	Message string
	Warning string
}

// secretEchoPatterns detects commands that would dump secrets to stdout.
var secretEchoPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)echo\s+\$\s*\(?(secret|api[_-]?key|token|password|credential)`),
	regexp.MustCompile(`(?i)echo\s+\$(SECRET|API[_-]?KEY|TOKEN|PASSWORD|CREDENTIAL)`),
	regexp.MustCompile(`(?i)^printenv`),
	regexp.MustCompile(`(?i)^env\s*\|`),
	regexp.MustCompile(`(?i)printenv\s*\|\s*grep`),
}

// matchesSecretEcho detects commands that would dump secrets to stdout.
func matchesSecretEcho(command string) bool {
	cmd := strings.TrimSpace(command)
	for _, p := range secretEchoPatterns {
		if p.MatchString(cmd) {
			return true
		}
	}
	return false
}

// ScanCommand checks a bash command for secrets before execution.
func ScanCommand(command string, cfg config.SecretScanConfig) CheckResult {
	// 1. Check for secret echo/dump commands first.
	if matchesSecretEcho(command) {
		return CheckResult{
			Block:   true,
			Message: "Command would expose secrets to stdout",
		}
	}

	// 2. Check if command matches an allow pattern.
	for _, ap := range cfg.AllowPatterns {
		re, err := regexp.Compile(ap)
		if err != nil {
			continue
		}
		if re.MatchString(command) {
			return CheckResult{}
		}
	}

	// 3. Check for inline secrets using regex patterns from config.
	for _, pat := range cfg.Patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		if match := re.FindString(command); match != "" {
			return CheckResult{
				Block:   true,
				Message: fmt.Sprintf("Possible secret detected in command: %s", truncate(match, 40)),
			}
		}
	}

	return CheckResult{}
}

// ScanFileContent checks file content being written for secrets.
func ScanFileContent(filePath string, content string, cfg config.SecretScanConfig) CheckResult {
	// 1. Check if the filename matches a blockFilePattern.
	for _, bfp := range cfg.BlockFilePatterns {
		re, err := regexp.Compile(bfp)
		if err != nil {
			continue
		}
		if re.MatchString(filePath) {
			return CheckResult{
				Block:   true,
				Message: fmt.Sprintf("Writing to sensitive file blocked: %s", filePath),
			}
		}
	}

	// 2. Check if content matches an allow pattern.
	for _, ap := range cfg.AllowPatterns {
		re, err := regexp.Compile(ap)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			return CheckResult{}
		}
	}

	// 3. Scan content line by line for secret patterns.
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		for _, pat := range cfg.Patterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			if match := re.FindString(line); match != "" {
				return CheckResult{
					Block:   true,
					Message: fmt.Sprintf("Possible secret detected in file %s: %s", filePath, truncate(match, 40)),
				}
			}
		}
	}

	return CheckResult{}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
