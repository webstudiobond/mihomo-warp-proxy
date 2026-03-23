package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFileNonExistent(t *testing.T) {
	dir := t.TempDir()
	err := ConfigFile(filepath.Join(dir, "nonexistent.yaml"))
	if err != nil {
		t.Errorf("missing source file should not error, got: %v", err)
	}
}

func TestConfigFileEmpty(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(src, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Errorf("empty source file should not error, got: %v", err)
	}

	// No backup should have been created for an empty file.
	if _, err := os.Stat(src + ".back"); !os.IsNotExist(err) {
		t.Error("backup file should not exist for empty source")
	}
}

func TestConfigFileCreatesBackup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")
	content := []byte("mode: rule\nmixed-port: 7890\n")

	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	back := src + ".back"
	got, err := os.ReadFile(back) // #nosec G304
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}

	if !bytes.Equal(got, content) {
		t.Errorf("backup content mismatch: got %q, want %q", got, content)
	}
}

func TestConfigFileBackupPermissions(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(src, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(src + ".back")
	if err != nil {
		t.Fatalf("backup file not found: %v", err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("backup file permissions: got %04o, want 0o600", perm)
	}
}

func TestConfigFileOverwritesExistingBackup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")
	back := src + ".back"

	oldContent := []byte("old content")
	newContent := []byte("new content")

	// Create a stale backup from a previous run.
	if err := os.WriteFile(back, oldContent, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(src, newContent, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(back) // #nosec G304
	if err != nil {
		t.Fatalf("backup file not found: %v", err)
	}

	if !bytes.Equal(got, newContent) {
		t.Errorf("backup not updated: got %q, want %q", got, newContent)
	}
}

func TestConfigFileSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real_config.yaml")
	link := filepath.Join(dir, "config.yaml")
	content := []byte("real content via symlink")

	if err := os.WriteFile(realFile, content, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	// Pass the symlink path — backup must copy the content, not create a
	// symlink backup.
	if err := ConfigFile(link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Backup is created next to the resolved real file.
	back := realFile + ".back"
	got, err := os.ReadFile(back) // #nosec G304
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}

	if !bytes.Equal(got, content) {
		t.Errorf("symlink backup content mismatch: got %q, want %q", got, content)
	}

	// Backup must be a regular file, not a symlink.
	info, err := os.Lstat(back)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("backup file must not be a symlink")
	}
}

func TestConfigFileSourceNotRegular(t *testing.T) {
	dir := t.TempDir()
	// A directory is not a regular file — must be rejected.
	err := ConfigFile(dir)
	if err == nil {
		t.Error("expected error for directory source, got nil")
	}
}

func TestIsDirWritable(t *testing.T) {
	dir := t.TempDir()
	if !isDirWritable(dir) {
		t.Error("temp dir should be writable")
	}

	if isDirWritable("/proc/1") {
		t.Error("/proc/1 should not be writable")
	}
}
