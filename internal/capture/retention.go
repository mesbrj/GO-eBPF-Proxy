package capture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Retention bounds a directory of secret-grade artifacts: a size cap AND an
// age cap (whichever is hit first) with oldest-first rotation, plus
// ephemeral-by-default cleanup unless Retain is set (the --retain flag).
type Retention struct {
	// Dir is the artifact directory to enforce bounds over.
	Dir string
	// MaxBytes is the total-size cap across all files in Dir. Zero disables
	// the size cap.
	MaxBytes int64
	// MaxAge is the age cap: any file older than MaxAge is evicted. Zero
	// disables the age cap.
	MaxAge time.Duration
	// Retain disables Cleanup's purge (the --retain flag).
	Retain bool
	// Clock supplies "now" for age evaluation; defaults to SystemClock.
	Clock Clock
}

// ErrWorldAccessibleTarget is returned when the target directory is
// group/other-accessible: refuse to write plaintext-equivalent secrets
// under it.
var ErrWorldAccessibleTarget = errors.New("capture: refusing to write under a world-accessible target")

// CheckTarget refuses to write under dir if it is group- or other-accessible
// in any way. A directory that does not exist yet is allowed (the writer
// creates it 0700). Call before creating artifacts in dir.
func CheckTarget(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("capture: stat %q: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %q has mode %o", ErrWorldAccessibleTarget, dir, perm)
	}
	return nil
}

// retentionFile is one directory entry considered for eviction.
type retentionFile struct {
	path    string
	size    int64
	modTime time.Time
}

// Enforce evicts files oldest-first until Dir's total size is within
// MaxBytes and no remaining file is older than MaxAge. A missing Dir is not
// an error (nothing to enforce yet).
func (r Retention) Enforce() error {
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("capture: read %q: %w", r.Dir, err)
	}

	clock := r.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	now := clock.Now()

	var files []retentionFile
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, retentionFile{path: filepath.Join(r.Dir, e.Name()), size: info.Size(), modTime: info.ModTime()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })

	var errs []error
	for _, f := range files {
		overAge := r.MaxAge > 0 && now.Sub(f.modTime) > r.MaxAge
		overSize := r.MaxBytes > 0 && total > r.MaxBytes
		if !overAge && !overSize {
			continue
		}
		if err := os.Remove(f.path); err != nil {
			errs = append(errs, fmt.Errorf("capture: evict %q: %w", f.path, err))
			continue
		}
		total -= f.size
	}
	return errors.Join(errs...)
}

// Cleanup wipes Dir's contents unless Retain is set -- the ephemeral-by-
// default teardown policy; --retain opts out. A missing Dir is not an error.
// SPEC_DEVIATION: design.md sketches Cleanup(retain bool); the retain flag is
// carried on the Retention struct instead, so Enforce and Cleanup share one
// config value rather than two independent sources of truth for it.
func (r Retention) Cleanup() error {
	if r.Retain {
		return nil
	}
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("capture: read %q: %w", r.Dir, err)
	}
	var errs []error
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(r.Dir, e.Name())); err != nil {
			errs = append(errs, fmt.Errorf("capture: remove %q: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}
