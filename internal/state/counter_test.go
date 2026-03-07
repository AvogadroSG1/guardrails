package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCounter_IncrementAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counter.json")

	c := &EditCounter{}
	c.Increment("src/main.go")
	c.Increment("src/app.py")

	if err := c.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.SourceEdits != 2 {
		t.Errorf("SourceEdits = %d, want 2", loaded.SourceEdits)
	}
	if len(loaded.LastEditedFiles) != 2 {
		t.Errorf("LastEditedFiles length = %d, want 2", len(loaded.LastEditedFiles))
	}
}

func TestCounter_Reset(t *testing.T) {
	c := &EditCounter{}
	c.Increment("a.go")
	c.Increment("b.go")
	c.Increment("c.go")

	if c.SourceEdits != 3 {
		t.Fatalf("SourceEdits = %d, want 3", c.SourceEdits)
	}

	c.Reset()

	if c.SourceEdits != 0 {
		t.Errorf("SourceEdits after reset = %d, want 0", c.SourceEdits)
	}
	if c.LastTestRun.IsZero() {
		t.Error("LastTestRun should be set after reset")
	}
	if len(c.LastEditedFiles) != 0 {
		t.Errorf("LastEditedFiles after reset = %d, want 0", len(c.LastEditedFiles))
	}
}

func TestCounter_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "counter.json")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load should not error for missing file, got: %v", err)
	}
	if c.SourceEdits != 0 {
		t.Errorf("SourceEdits = %d, want 0", c.SourceEdits)
	}
}

func TestCounter_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "counter.json")

	if err := os.WriteFile(path, []byte("{corrupt json!!!"), 0644); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load should not error for corrupt file, got: %v", err)
	}
	if c.SourceEdits != 0 {
		t.Errorf("SourceEdits = %d, want 0", c.SourceEdits)
	}
}
