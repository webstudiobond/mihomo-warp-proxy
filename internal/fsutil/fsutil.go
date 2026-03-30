// Package fsutil provides atomic filesystem operations to ensure file
// integrity during writes and updates.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// atomicFinish syncs, closes and renames the temp file to the final destination.
func atomicFinish(f *os.File, tmpName, dst string) error {
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename to destination: %w", err)
	}
	return nil
}

func createAtomicTemp(dst string, perm os.FileMode) (*os.File, string, error) {
	dir := filepath.Dir(dst)
	f, err := os.CreateTemp(dir, filepath.Base(dst)+".*")
	if err != nil {
		return nil, "", fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()          //nolint:errcheck // cleanup on error
		_ = os.Remove(tmpName) //nolint:errcheck // cleanup on error
		return nil, "", fmt.Errorf("chmod temp file: %w", err)
	}
	return f, tmpName, nil
}

// AtomicWrite writes data to filename atomically.
func AtomicWrite(filename string, data []byte, perm os.FileMode) error {
	f, tmpName, err := createAtomicTemp(filename, perm)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = f.Close()          //nolint:errcheck // cleanup on failure
			_ = os.Remove(tmpName) //nolint:errcheck // cleanup on failure
		}
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	if err := atomicFinish(f, tmpName, filename); err != nil {
		return err
	}
	done = true
	return nil
}

// IsDirWritable probes write access to dir by attempting to create and
// immediately remove a temporary file. This is the only reliable cross-platform
// method — permission bits alone do not account for ACLs, read-only mounts,
// or quota exhaustion.
func IsDirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".write_probe_*.tmp")
	if err != nil {
		return false
	}
	_ = f.Close()           //nolint:errcheck // probe cleanup
	_ = os.Remove(f.Name()) //nolint:errcheck // probe cleanup
	return true
}
