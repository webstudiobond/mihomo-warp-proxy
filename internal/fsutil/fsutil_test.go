package fsutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test_write.txt")
	data := []byte("hello world")

	if err := AtomicWrite(file, data, 0600); err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Got permissions %v, want 0600", info.Mode().Perm())
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Got %q, want %q", got, data)
	}
}
