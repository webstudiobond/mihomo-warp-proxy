// Package backup provides atomic backup of the mihomo config file.
// A backup is created before any mutation so that a failed config update
// never leaves the user without a recoverable previous state.
package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/webstudiobond/mihomo-warp-proxy/internal/fsutil"
	"github.com/webstudiobond/mihomo-warp-proxy/internal/validate"
)

// maxBackupSize mirrors the config file size limit in mihomo/config.go.
// Both limits must be kept in sync — a config that passes the backup check
// must also pass the parse check on the next read.
const maxBackupSize = 1024 * 1024 // 1 MB

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

	if err := validate.Path(src, "backup_source"); err != nil {
		return fmt.Errorf("backup: security violation on resolved path: %w", err)
	}

	dir := filepath.Dir(src)
	if !isDirWritable(dir) {
		// Non-writable parent means we are operating on a read-only mount.
		// Log-worthy but not fatal — the caller decides whether to proceed.
		return fmt.Errorf("backup: parent directory %q is not writable", dir)
	}

	return atomicCopy(src, src+".back")
}

// atomicCopy copies src to dst via a temporary file in tmpDir, then renames
// the temporary file to dst. This ensures dst is never partially written.
func atomicCopy(src, dst string) error {
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

	limited := io.LimitReader(in, maxBackupSize+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("backup: copy content to temp file: %w", err)
	}
	if int64(len(buf)) > maxBackupSize {
		return fmt.Errorf("backup: source file %q exceeds 1MB limit", src)
	}

	return fsutil.AtomicWrite(dst, buf, 0600)
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
	_ = f.Close()
	_ = os.Remove(f.Name())
	return true
}
