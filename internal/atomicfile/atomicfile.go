// Package atomicfile writes files that only ever appear complete.
package atomicfile

import (
	"io"
	"os"
	"path/filepath"
)

// Write creates or replaces path with whatever fill writes.
//
// The data goes to a temporary file in the same directory, which is renamed
// over path only after fill succeeds and the data is flushed to disk. A failed
// or interrupted write therefore never leaves a truncated file behind, and any
// existing file at path is left untouched. The file is created with mode 0600
// (owner read/write only) because CyberArkHound's outputs describe the vault in
// detail.
func Write(path string, fill func(w io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp already uses 0600; be explicit in case that ever changes.
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if err = fill(tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
