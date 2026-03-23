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

func TestAtomicCopy(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "src.txt")
	dstFile := filepath.Join(dir, "dst.txt")
	data := []byte("hello copy")

	if err := os.WriteFile(srcFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := AtomicCopy(srcFile, dstFile, 0600, 1024); err != nil {
		t.Fatalf("AtomicCopy failed: %v", err)
	}

	got, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read copied file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Got %q, want %q", got, data)
	}
}

func TestAtomicCopyExceedsLimit(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "src.txt")
	dstFile := filepath.Join(dir, "dst.txt")

	if err := os.WriteFile(srcFile, []byte("hello limit"), 0600); err != nil {
		t.Fatal(err)
	}

	err := AtomicCopy(srcFile, dstFile, 0600, 5)
	if err == nil {
		t.Fatal("Expected error when exceeding limit, got nil")
	}
	if _, err := os.Stat(dstFile); !os.IsNotExist(err) {
		t.Errorf("Expected destination file to not exist on failure")
	}
}
