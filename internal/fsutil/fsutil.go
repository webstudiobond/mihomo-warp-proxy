package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to filename atomically.
func AtomicWrite(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	f, err := os.CreateTemp(dir, filepath.Base(filename)+".*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()
	defer os.Remove(tmpName)
	defer f.Close()

	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpName, filename)
}

// AtomicCopy copies a file from src to dst atomically.
func AtomicCopy(src, dst string, perm os.FileMode, maxSize int64) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source %q: %w", src, err)
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	f, err := os.CreateTemp(dir, filepath.Base(dst)+".*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()
	defer os.Remove(tmpName)
	defer f.Close()

	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	limited := io.LimitReader(in, maxSize+1)
	n, err := io.Copy(f, limited)
	if err != nil {
		return fmt.Errorf("copy content to temp file: %w", err)
	}
	if n > maxSize {
		return fmt.Errorf("source file %q exceeds limit of %d bytes", src, maxSize)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpName, dst)
}
