// Package capture writes the proxy relay's outbound leg to pcap/pcapng,
// pairs it with the uprobe-emitted NSS keylog, and enforces secret-grade,
// bounded retention on the resulting artifacts. No TLS termination, no MITM:
// capture is a passive observer of ciphertext plus the app's own key material.
package capture

import (
	"sync"
	"time"
)

// Clock is the single timestamp source the capture writer (and any component
// that must agree with it) uses, so packet and key-material timestamps never
// drift onto different clocks. See CAPTURE-02: capture and keylog timestamps
// must align for tshark offline decryption.
type Clock interface {
	// Now returns the current time. Implementations must return
	// monotonically non-decreasing values across calls.
	Now() time.Time
}

// SystemClock is the production Clock, backed by time.Now (which carries a
// monotonic reading on every platform Go supports).
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// ManualClock is a deterministic, injectable Clock for tests: it starts at a
// fixed instant and only advances when told to, so timestamp-alignment tests
// can assert exact deltas instead of racing the wall clock.
type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewManualClock returns a ManualClock starting at start.
func NewManualClock(start time.Time) *ManualClock {
	return &ManualClock{now: start}
}

// Now returns the current simulated time.
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the simulated clock forward by d and returns the new time. A
// non-positive d is ignored so Now never moves backward.
func (c *ManualClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > 0 {
		c.now = c.now.Add(d)
	}
	return c.now
}
