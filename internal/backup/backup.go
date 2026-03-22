// Package backup provides atomic backup of the mihomo config file.
// A backup is created before any mutation so that a failed config update
// never leaves the user without a recoverable previous state.
package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ConfigFile atomically copies src to src+".back" if src exists, is non-empty,
// and its parent directory is writable by the current process.
//
// The copy is written to a temporary file in the same directory as src and
// then renamed into place. Same-directory placement guarantees the rename is
// atomic on POSIX (single filesystem, no cross-device move).
//
// A missing src is not an error: there is simply nothing to back up on first run.
func ConfigFile(src string) error {
	// Resolve symlinks so the backup is placed next to the real file, not the
	// link. os.Open below follows the symlink automatically for reading, but
	// filepath.Dir(src) would point to the link's directory otherwise.
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("backup: resolve path %q: %w", src, err)
	}

	dir := filepath.Dir(src)
	if !isDirWritable(dir) {
		// Non-writable parent means we are operating on a read-only mount.
		// Log-worthy but not fatal — the caller decides whether to proceed.
		return fmt.Errorf("backup: parent directory %q is not writable", dir)
	}

	return atomicCopy(src, src+".back", dir)
}

// atomicCopy copies src to dst via a temporary file in tmpDir, then renames
// the temporary file to dst. This ensures dst is never partially written.
func atomicCopy(src, dst, tmpDir string) error {
	// #nosec G304 -- File inclusion is intended here. src is either the fixed
	// mihomo config path or its direct symlink target, protected by validate.Path.
	in, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // A missing src is not an error
		}
		return fmt.Errorf("backup: open source %q: %w", src, err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("backup: stat opened file %q: %w", src, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup: %q is not a regular file", src)
	}

	if info.Size() == 0 {
		return nil
	}

	tmp, err := os.CreateTemp(tmpDir, ".config_backup_*.tmp")
	if err != nil {
		return fmt.Errorf("backup: create temp file in %q: %w", tmpDir, err)
	}
	tmpName := tmp.Name()

	// Unconditional cleanup: remove the temp file on any failure path.
	// On success the file has already been renamed, so Remove is a no-op.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("backup: chmod temp file: %w", err)
	}

	if _, err := io.Copy(tmp, in); err != nil {
		return fmt.Errorf("backup: copy content to temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("backup: sync temp file: %w", err)
	}

	// Close before rename — required on some POSIX implementations.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("backup: close temp file: %w", err)
	}

	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("backup: rename %q -> %q: %w", tmpName, dst, err)
	}

	return nil
}

// isDirWritable probes write access to dir by attempting to create and
// immediately remove a temporary file. This is the only reliable cross-platform
// method — permission bits alone do not account for ACLs, read-only mounts,
// or quota exhaustion.
func isDirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".write_probe_*.tmp")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}
