// Package capture writes the proxy relay's outbound leg to pcap/pcapng,
// pairs it with the NSS keylog the LD_PRELOAD interposer emits, and enforces
// secret-grade, bounded retention on the resulting artifacts. No TLS
// termination, no MITM: capture is a passive observer of ciphertext plus the
// app's own key material.
package capture

import "time"

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
