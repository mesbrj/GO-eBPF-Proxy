package keylog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Writer appends validated, deduplicated NSS keylog lines to a secret-grade
// file: 0600 inside a 0700 directory, O_APPEND, newline-terminated, with
// concurrent writes serialised. See AD-006: keylog and capture are treated as
// plaintext-equivalent secrets.
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	seen map[string]struct{}
}

// NewWriter opens (creating if needed) the keylog file at path, creating its
// parent directory 0700 and the file 0600.
func NewWriter(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304,G302 -- path is operator-supplied config, not raw user input; 0600 is the intended secret-grade mode
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, seen: make(map[string]struct{})}, nil
}

// Append validates line as a well-formed NSS keylog line, rejecting it
// (without writing) if malformed, then appends it followed by a newline
// unless the same (label, client_random, secret) triple was already written.
// Concurrent callers are serialised.
func (w *Writer) Append(line string) error {
	if err := ValidateLine(line); err != nil {
		return err
	}
	fields := strings.Fields(line)
	key := fields[0] + "|" + fields[1] + "|" + fields[2]

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, dup := w.seen[key]; dup {
		return nil
	}
	if _, err := w.f.WriteString(line + "\n"); err != nil {
		return err
	}
	w.seen[key] = struct{}{}
	return nil
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	return w.f.Close()
}
