package capture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Retention bounds the captures this sidecar owns in the capture directory,
// and only those (door 2). An owned capture is a regular file directly in
// Template's directory whose name is one CreateRunCapture gives:
// <stem>-<epoch><ext> or <stem>-<epoch>-<n><ext>. MaxBytes limits what the
// owned captures hold together, this run's included: Room is what it leaves
// for this run's capture, whose Writer stops capture there, and no file is
// ever deleted for size (AD-020). MaxAge deletes finished owned captures. The
// keylog file and every other entry of the directory, a fixed-name capture an
// earlier version wrote included, are never counted or deleted.
type Retention struct {
	// Template is the --capture-path every run's capture is named from.
	Template string
	// Run is this run's capture file, "" while there is none. Enforce never
	// deletes it and OwnedBytes never counts it: every other owned capture is
	// a finished one. It is the only file Cleanup deletes.
	Run string
	// MaxBytes is the most the owned captures may hold together. Zero
	// disables the limit.
	MaxBytes int64
	// MaxAge is the age cap: a finished owned capture whose mtime is older
	// than MaxAge is deleted. Zero disables the age cap.
	MaxAge time.Duration
	// Retain keeps Run through Cleanup (the --retain flag).
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

// retentionFile is one finished owned capture.
type retentionFile struct {
	path    string
	size    int64
	modTime time.Time
}

// finished returns the finished owned captures: every owned capture in the
// directory but Run. Each entry is checked with Lstat, so a symlink is never
// one. A missing directory holds none.
func (r Retention) finished() ([]retentionFile, error) {
	dir, stem, ext := splitTemplate(r.Template)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("capture: read %q: %w", dir, err)
	}
	owned := regexp.MustCompile("^" + regexp.QuoteMeta(stem) + `-[0-9]+(-[0-9]+)?` + regexp.QuoteMeta(ext) + "$")
	var files []retentionFile
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if !owned.MatchString(e.Name()) || path == filepath.Clean(r.Run) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue // gone since it was listed, or not a regular file
		}
		files = append(files, retentionFile{path: path, size: info.Size(), modTime: info.ModTime()})
	}
	return files, nil
}

// OwnedBytes sums the sizes (st_size) of the finished owned captures.
func (r Retention) OwnedBytes() (int64, error) {
	files, err := r.finished()
	var total int64
	for _, f := range files {
		total += f.size
	}
	return total, err
}

// Room returns what MaxBytes leaves for this run's capture: MaxBytes less
// OwnedBytes, which is zero or less once the finished captures alone reach
// it. Without MaxBytes there is no limit, and Room returns 0, which
// Options.Room takes as none.
func (r Retention) Room() (int64, error) {
	if r.MaxBytes <= 0 {
		return 0, nil
	}
	owned, err := r.OwnedBytes()
	return r.MaxBytes - owned, err
}

// Enforce runs one age pass: it deletes every finished owned capture whose
// mtime is older than MaxAge. It never deletes this run's capture, and never
// deletes for size. A missing directory is not an error.
func (r Retention) Enforce() error {
	if r.MaxAge <= 0 {
		return nil
	}
	files, err := r.finished()
	if err != nil {
		return err
	}
	clock := r.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	now := clock.Now()

	var errs []error
	for _, f := range files {
		if now.Sub(f.modTime) <= r.MaxAge {
			continue
		}
		if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("capture: delete expired %q: %w", f.path, err))
		}
	}
	return errors.Join(errs...)
}

// Cleanup deletes this run's capture unless Retain is set -- the
// ephemeral-by-default teardown policy; --retain opts out. It deletes nothing
// else: a capture kept by an earlier run is never this run's to delete (AC 17,
// AC 20). A capture already gone is not an error.
// SPEC_DEVIATION: design.md sketches Cleanup(retain bool); the retain flag is
// carried on the Retention struct instead, so Enforce and Cleanup share one
// config value rather than two independent sources of truth for it.
func (r Retention) Cleanup() error {
	if r.Retain || r.Run == "" {
		return nil
	}
	if err := os.Remove(r.Run); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("capture: remove %q: %w", r.Run, err)
	}
	return nil
}
