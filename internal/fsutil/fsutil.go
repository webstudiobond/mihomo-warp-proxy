package fsutil

import (
	"fmt"
	"io"
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
		_ = f.Close()
		_ = os.Remove(tmpName)
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
			_ = f.Close()
			_ = os.Remove(tmpName)
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

// AtomicCopy copies a file from src to dst atomically.
func AtomicCopy(src, dst string, perm os.FileMode, maxSize int64) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source %q: %w", src, err)
	}
	defer in.Close()

	f, tmpName, err := createAtomicTemp(dst, perm)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = f.Close()
			_ = os.Remove(tmpName)
		}
	}()

	limited := io.LimitReader(in, maxSize+1)
	n, err := io.Copy(f, limited)
	if err != nil {
		return fmt.Errorf("copy content to temp file: %w", err)
	}
	if n > maxSize {
		return fmt.Errorf("source file %q exceeds limit of %d bytes", src, maxSize)
	}
	if err := atomicFinish(f, tmpName, dst); err != nil {
		return err
	}
	done = true
	return nil
}
