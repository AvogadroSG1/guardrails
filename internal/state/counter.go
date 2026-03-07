package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// EditCounter tracks source file edits between test runs.
type EditCounter struct {
	SourceEdits     int       `json:"sourceEdits"`
	LastTestRun     time.Time `json:"lastTestRun"`
	LastEditedFiles []string  `json:"lastEditedFiles"`
}

// Load reads an EditCounter from a JSON file.
// Missing file returns a zero counter (no error).
// Corrupt JSON returns a zero counter (no error).
func Load(path string) (*EditCounter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return &EditCounter{}, nil
	}

	var c EditCounter
	if err := json.Unmarshal(data, &c); err != nil {
		return &EditCounter{}, nil
	}
	return &c, nil
}

// Save writes the counter to a JSON file, creating parent directories as needed.
func (c *EditCounter) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Increment bumps SourceEdits and appends filePath to LastEditedFiles (keeping last 20).
func (c *EditCounter) Increment(filePath string) {
	c.SourceEdits++
	c.LastEditedFiles = append(c.LastEditedFiles, filePath)
	if len(c.LastEditedFiles) > 20 {
		c.LastEditedFiles = c.LastEditedFiles[len(c.LastEditedFiles)-20:]
	}
}

// Reset sets SourceEdits to 0, LastTestRun to now, and clears LastEditedFiles.
func (c *EditCounter) Reset() {
	c.SourceEdits = 0
	c.LastTestRun = time.Now()
	c.LastEditedFiles = nil
}
