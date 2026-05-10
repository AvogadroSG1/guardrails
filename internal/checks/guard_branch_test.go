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
			result := GuardBranch(tt.branch, tt.repoRoot, false, cfg, TargetInfo{})
			if result.Block != tt.want {
				t.Errorf("GuardBranch(%q, %q) block = %v, want %v; message = %q",
					tt.branch, tt.repoRoot, result.Block, tt.want, result.Message)
			}
		})
	}
}

func TestGuardBranch_StagedChanges(t *testing.T) {
	cfg := config.Default()

	result := GuardBranch("feature/foo", "/Users/test/code/myproject", true, cfg, TargetInfo{})
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

	result := GuardBranch("main", "/Users/test/my-content-repo", false, cfg, TargetInfo{})
	if result.Block {
		t.Errorf("expected allow for custom-excluded repo, got block: %q", result.Message)
	}
}

func TestGuardBranch_BypassChecksRunWhenCWDOutsideRepo(t *testing.T) {
	cfg := config.Default()
	// branch == "" simulates CWD outside any git repo (gitCurrentBranch returns "").
	// Target-based bypass checks must still fire in this state.
	tests := []struct {
		name   string
		target TargetInfo
		want   bool
	}{
		{
			name: "cross-repo write to protected branch from outside any repo",
			target: TargetInfo{
				FilePath: "/Users/test/code/repo-b/src/app.py",
				Branch:   "main",
				RepoRoot: "/Users/test/code/repo-b",
			},
			want: true,
		},
		{
			name: "temp script with git commit from outside any repo",
			target: TargetInfo{
				FilePath: "/tmp/evil.sh",
				Content:  "git commit -m 'bypass'",
			},
			want: true,
		},
		{
			name: "benign write from outside any repo",
			target: TargetInfo{
				FilePath: "/tmp/helper.py",
				Content:  "print('hello')",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// branch="" and repoRoot="" simulate CWD not in any git repo.
			result := GuardBranch("", "", false, cfg, tt.target)
			if result.Block != tt.want {
				t.Errorf("GuardBranch outside-repo for %q: Block=%v, want %v; message=%q",
					tt.target.FilePath, result.Block, tt.want, result.Message)
			}
		})
	}
}

func TestGuardBranch_TempDirBypass(t *testing.T) {
	cfg := config.Default()
	// CWD repo is on a safe feature branch — normal protected-branch check passes.
	cwdBranch := "feature/my-work"
	repoRoot := "/Users/test/code/myproject"

	tests := []struct {
		name           string
		filePath       string
		content        string
		targetRepoRoot string // set when the target file is inside a git repo
		want           bool   // true = block
	}{
		{
			name:     "git commit in /tmp script",
			filePath: "/tmp/deploy.sh",
			content:  "#!/bin/bash\ngit commit -m 'automated'",
			want:     true,
		},
		{
			name:     "git push in /tmp script",
			filePath: "/tmp/push.sh",
			content:  "git push origin main",
			want:     true,
		},
		{
			name:     "git reset in /tmp script",
			filePath: "/tmp/fix.sh",
			content:  "git reset HEAD~1",
			want:     true,
		},
		{
			name:     "git checkout main in /tmp script",
			filePath: "/tmp/script.sh",
			content:  "git checkout main",
			want:     true,
		},
		{
			name:     "git switch main in /tmp script",
			filePath: "/tmp/script.sh",
			content:  "git switch main",
			want:     true,
		},
		{
			name:     "git checkout feature branch in /tmp (safe — not a protected branch)",
			filePath: "/tmp/script.sh",
			content:  "git checkout feature/my-work",
			want:     false,
		},
		{
			name:     "innocent python script in /tmp",
			filePath: "/tmp/helper.py",
			content:  "print('hello world')\nx = 1 + 2",
			want:     false,
		},
		{
			name:     "git push in /var/tmp script",
			filePath: "/var/tmp/script.sh",
			content:  "git push origin develop",
			want:     true,
		},
		{
			// In real usage gitRepoRootForPath resolves the repo root for in-project
			// files; phase 6a only fires when targetRepoRoot is empty (no git repo).
			name:           "git commit in in-project file (has git repo root — phase 6a skips)",
			filePath:       "/Users/test/code/myproject/scripts/deploy.sh",
			content:        "git commit -m 'automated'",
			targetRepoRoot: repoRoot,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := TargetInfo{
				FilePath: tt.filePath,
				Content:  tt.content,
				RepoRoot: tt.targetRepoRoot,
			}
			result := GuardBranch(cwdBranch, repoRoot, false, cfg, target)
			if result.Block != tt.want {
				t.Errorf("GuardBranch temp-dir check for %q: Block=%v, want %v; message=%q",
					tt.filePath, result.Block, tt.want, result.Message)
			}
		})
	}
}

func TestGuardBranch_CrossRepoWrite(t *testing.T) {
	cfg := config.Default()
	cfg.RepoExclusions = append(cfg.RepoExclusions, "/Users/test/my-content-repo")
	cwdBranch := "feature/my-work"
	cwdRepoRoot := "/Users/test/code/repo-a"

	tests := []struct {
		name           string
		targetFilePath string
		targetBranch   string
		targetRepoRoot string
		want           bool // true = block
	}{
		{
			name:           "write to different repo on main",
			targetFilePath: "/Users/test/code/repo-b/src/app.py",
			targetBranch:   "main",
			targetRepoRoot: "/Users/test/code/repo-b",
			want:           true,
		},
		{
			name:           "write to different repo on master",
			targetFilePath: "/Users/test/code/other-project/main.go",
			targetBranch:   "master",
			targetRepoRoot: "/Users/test/code/other-project",
			want:           true,
		},
		{
			name:           "write to different repo on develop",
			targetFilePath: "/Users/test/code/repo-b/README.md",
			targetBranch:   "develop",
			targetRepoRoot: "/Users/test/code/repo-b",
			want:           true,
		},
		{
			name:           "write to different repo on release branch",
			targetFilePath: "/Users/test/code/repo-b/config.yaml",
			targetBranch:   "release/1.0",
			targetRepoRoot: "/Users/test/code/repo-b",
			want:           true,
		},
		{
			name:           "write to different repo on feature branch (safe)",
			targetFilePath: "/Users/test/code/repo-b/src/app.py",
			targetBranch:   "feature/their-work",
			targetRepoRoot: "/Users/test/code/repo-b",
			want:           false,
		},
		{
			name:           "write to same repo root (cross-repo check skips)",
			targetFilePath: "/Users/test/code/repo-a/src/util.py",
			targetBranch:   "feature/my-work",
			targetRepoRoot: cwdRepoRoot,
			want:           false, // same repo; phase 4 governs via cwdBranch
		},
		{
			name:           "target RepoRoot empty (not in a git repo)",
			targetFilePath: "/Users/test/documents/notes.txt",
			targetBranch:   "",
			targetRepoRoot: "",
			want:           false,
		},
		// Fix: cross-repo check must honor RepoExclusions for the target repo.
		{
			name:           "write to excluded target repo on main (should allow)",
			targetFilePath: "/Users/test/my-content-repo/post.md",
			targetBranch:   "main",
			targetRepoRoot: "/Users/test/my-content-repo",
			want:           false, // excluded via cfg.RepoExclusions set below
		},
		// Fix: cross-repo check must honor ObsidianNotes exclusion for target.
		{
			name:           "write to ObsidianNotes target repo on main (should allow)",
			targetFilePath: "/Users/test/ObsidianNotes/Work/note.md",
			targetBranch:   "main",
			targetRepoRoot: "/Users/test/ObsidianNotes/Work",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := TargetInfo{
				FilePath: tt.targetFilePath,
				Branch:   tt.targetBranch,
				RepoRoot: tt.targetRepoRoot,
			}
			result := GuardBranch(cwdBranch, cwdRepoRoot, false, cfg, target)
			if result.Block != tt.want {
				t.Errorf("GuardBranch cross-repo for %q (branch %q): Block=%v, want %v; message=%q",
					tt.targetFilePath, tt.targetBranch, result.Block, tt.want, result.Message)
			}
		})
	}
}

func TestGuardBranch_IndirectWrite(t *testing.T) {
	cfg := config.Default()
	cwdBranch := "feature/my-work"
	repoRoot := "/Users/test/code/myproject"

	tests := []struct {
		name     string
		filePath string
		content  string
		want     bool
	}{
		{
			name:     "python open write to repoRoot",
			filePath: "/Users/test/code/other-repo/script.py",
			content:  "with open('/Users/test/code/myproject/main.go', 'w') as f:\n    f.write('evil')",
			want:     true,
		},
		{
			name:     "shell redirect into repoRoot",
			filePath: "/Users/test/workspace/build.sh",
			content:  "echo 'evil' > /Users/test/code/myproject/src/app.go",
			want:     true,
		},
		{
			name:     "cp into repoRoot",
			filePath: "/tmp/inject.sh",
			content:  "cp ./evil.so /Users/test/code/myproject/lib/",
			want:     true,
		},
		{
			name:     "read-only access to repoRoot (cat)",
			filePath: "/tmp/read.sh",
			content:  "cat /Users/test/code/myproject/main.go",
			want:     false,
		},
		{
			name:     "python open read from repoRoot",
			filePath: "/tmp/read.py",
			content:  "with open('/Users/test/code/myproject/main.go', 'r') as f:\n    data = f.read()",
			want:     false,
		},
		{
			name:     "write to unrelated path",
			filePath: "/tmp/unrelated.sh",
			content:  "echo 'data' > /some/other/path/file.txt",
			want:     false,
		},
		// Regression: cat suppression must not override redirect into repoRoot.
		{
			name:     "cat reading from repoRoot then redirecting elsewhere (safe)",
			filePath: "/tmp/read.sh",
			content:  "cat /Users/test/code/myproject/main.go > /tmp/out.txt",
			want:     false,
		},
		{
			name:     "cat reading from elsewhere then redirecting into repoRoot (write)",
			filePath: "/tmp/write.sh",
			content:  "cat /some/source.txt > /Users/test/code/myproject/main.go",
			want:     true,
		},
		// Regression: open() without explicit mode should not block (defaults to read).
		{
			name:     "python open without mode (defaults to read)",
			filePath: "/tmp/read.py",
			content:  "data = open('/Users/test/code/myproject/main.go').read()",
			want:     false,
		},
		// Fix: open() in r+ (read-write) mode must block.
		{
			name:     "python open r+ mode (read-write) must block",
			filePath: "/tmp/rw.py",
			content:  "f = open('/Users/test/code/myproject/main.go', 'r+')",
			want:     true,
		},
		// Fix: >= in code containing repoRoot must not be treated as redirect.
		{
			name:     "comparison >= containing repoRoot path in string (no redirect)",
			filePath: "/tmp/check.py",
			content:  "if version >= '/Users/test/code/myproject/v2':",
			want:     false,
		},
		// Fix: sibling directory with repoRoot as substring must not match.
		{
			name:     "write to sibling directory whose path contains repoRoot",
			filePath: "/tmp/sibling.sh",
			content:  "echo data > /Users/test/code/myproject2/file.go",
			want:     false,
		},
		// Fix: cp with repoRoot as source (not destination) must not block.
		{
			name:     "cp with repoRoot as source, /tmp as destination",
			filePath: "/tmp/backup.sh",
			content:  "cp /Users/test/code/myproject/main.go /tmp/backup.go",
			want:     false,
		},
		// Fix: write flag pointing to non-repo path must not block when repoRoot is only a read arg.
		{
			name:     "--output pointing to /tmp while repoRoot is a read arg",
			filePath: "/tmp/convert.sh",
			content:  "tool --output /tmp/out.txt /Users/test/code/myproject/input.go",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := TargetInfo{
				FilePath: tt.filePath,
				Content:  tt.content,
			}
			result := GuardBranch(cwdBranch, repoRoot, false, cfg, target)
			if result.Block != tt.want {
				t.Errorf("GuardBranch indirect-write for %q: Block=%v, want %v; message=%q",
					tt.filePath, result.Block, tt.want, result.Message)
			}
		})
	}
}

func TestGuardBranch_BashCommandWrite(t *testing.T) {
	cfg := config.Default()
	cwdBranch := "feature/my-work"
	repoRoot := "/Users/test/code/myproject"

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "shell redirect > to repoRoot path",
			command: "./evil > /Users/test/code/myproject/main.go",
			want:    true,
		},
		{
			name:    "shell append >> to repoRoot path",
			command: "./evil >> /Users/test/code/myproject/config.yaml",
			want:    true,
		},
		{
			name:    "pipe to tee targeting repoRoot",
			command: "./evil | tee /Users/test/code/myproject/src/app.go",
			want:    true,
		},
		{
			name:    "--output flag pointing to repoRoot",
			command: "./evil --output /Users/test/code/myproject/main.go",
			want:    true,
		},
		{
			name:    "-o flag pointing to repoRoot",
			command: "./evil -o /Users/test/code/myproject/main.go",
			want:    true,
		},
		{
			name:    "--file flag pointing to repoRoot",
			command: "./evil --file /Users/test/code/myproject/config.json",
			want:    true,
		},
		{
			name:    "cat read from repoRoot (no write)",
			command: "cat /Users/test/code/myproject/main.go",
			want:    false,
		},
		{
			name:    "redirect to /tmp (not repoRoot)",
			command: "./evil > /tmp/output.txt",
			want:    false,
		},
		{
			name:    "command with no mention of repoRoot",
			command: "go build ./...",
			want:    false,
		},
		// Regression: first repoRoot occurrence is a read arg; second is the redirect target.
		{
			name:    "cat reading from repoRoot then redirecting into repoRoot",
			command: "cat /Users/test/code/myproject/in.go > /Users/test/code/myproject/out.go",
			want:    true,
		},
		// /tmpfile must not match /tmp/ prefix check.
		{
			name:    "path starting with /tmp but not a temp subpath",
			command: "./evil > /tmpfile",
			want:    false, // /tmpfile is not in /tmp/ — no repoRoot involved, so also no block
		},
		// Fix: sibling directory whose path contains repoRoot as substring must not block.
		{
			name:    "redirect into sibling directory (not actually repoRoot)",
			command: "./evil > /Users/test/code/myproject2/file.go",
			want:    false,
		},
		// Fix: => (fat arrow) containing repoRoot must not be treated as redirect.
		{
			name:    "fat arrow => in command containing repoRoot path",
			command: "map.put(key => /Users/test/code/myproject/file)",
			want:    false,
		},
		// Fix: cp/mv with repoRoot as source (not destination) must not block.
		{
			name:    "cp with repoRoot as source must allow",
			command: "cp /Users/test/code/myproject/src/app.go /tmp/backup.go",
			want:    false,
		},
		// Fix: write flag pointing to non-repo path must not block even when repoRoot appears elsewhere.
		{
			name:    "--output pointing to /tmp while repoRoot is a read arg",
			command: "tool --output /tmp/out.txt /Users/test/code/myproject/input.go",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := TargetInfo{Command: tt.command}
			result := GuardBranch(cwdBranch, repoRoot, false, cfg, target)
			if result.Block != tt.want {
				t.Errorf("GuardBranch bash-command for %q: Block=%v, want %v; message=%q",
					tt.command, result.Block, tt.want, result.Message)
			}
		})
	}
}
