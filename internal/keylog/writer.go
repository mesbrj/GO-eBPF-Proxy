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
	sink func(line string)
	gate func() bool
}

// WriterOption configures optional Writer behavior.
type WriterOption func(*Writer)

// WithSink hands sink every line Append writes to the keylog file -- valid
// and not a duplicate -- right after writing it, in append order. The
// sidecar streams those lines into its capture this way (AD-018).
func WithSink(sink func(line string)) WriterOption {
	return func(w *Writer) { w.sink = sink }
}

// WithGate makes Append discard every valid line while open reports false:
// the line is not written to the keylog file, not handed to the sink and not
// added to the duplicate set, and Append returns nil. A malformed line is
// still rejected. The sidecar keeps the gate open only while capture is
// active, so no key is kept for traffic that is not captured (AD-023). A nil
// open, the default, never discards.
func WithGate(open func() bool) WriterOption {
	return func(w *Writer) { w.gate = open }
}

// NewWriter opens (creating if needed) the keylog file at path, creating its
// parent directory 0700 and the file 0600.
func NewWriter(path string, opts ...WriterOption) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304,G302 -- path is operator-supplied config, not raw user input; 0600 is the intended secret-grade mode
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, seen: make(map[string]struct{})}
	for _, o := range opts {
		o(w)
	}
	return w, nil
}

// Append validates line as a well-formed NSS keylog line, rejecting it
// (without writing) if malformed. It then discards it while the gate (see
// WithGate) is closed, and otherwise appends it followed by a newline unless
// the same (label, client_random, secret) triple was already written.
// Concurrent callers are serialised.
func (w *Writer) Append(line string) error {
	if err := ValidateLine(line); err != nil {
		return err
	}
	fields := strings.Fields(line)
	key := fields[0] + "|" + fields[1] + "|" + fields[2]

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.gate != nil && !w.gate() {
		return nil
	}
	if _, dup := w.seen[key]; dup {
		return nil
	}
	if _, err := w.f.WriteString(line + "\n"); err != nil {
		return err
	}
	w.seen[key] = struct{}{}
	if w.sink != nil {
		w.sink(line)
	}
	return nil
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	return w.f.Close()
}
