// Package capturetest validates capture artifacts offline: it runs tshark
// over a capture paired with its NSS keylog and returns the decrypted
// application data, automating Feature 03's acceptance
// (tshark -r dump.pcapng -o "tls.keylog_file:sslkeylog.log"). It is test
// support only, kept out of package capture so the sidecar binary never
// carries a tshark dependency it does not use.
package capturetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// AppDataFilter is the tshark display filter for a decrypted session's
// application data, whichever protocol the session negotiated over ALPN.
// Filtering on "http" alone is a trap: tshark dissects HTTP/2 with a
// separate "http2" dissector that "http" never matches, and h2 is what any
// modern client negotiates by default (curl against example.com, Go's own
// http2 transport, every browser). An h2 session therefore yields zero
// matching frames under "http" even when the capture is complete and its
// keys decrypt perfectly -- indistinguishable from a total capture or
// decryption failure. Matching both dissectors keeps the offline-validation
// workflow (CAPTURE-04/CAPTURE-11) ALPN-agnostic.
const AppDataFilter = "http or http2"

// TsharkArgs returns the tshark arguments that pair a capture file with its
// NSS keylog for offline decryption: tshark -r <pcap> -o "tls.keylog_file:<keylog>".
// An empty keylogPath still emits the option, as "tls.keylog_file:", which
// clears any keylog set in the invoking user's Wireshark preferences: only
// the secrets embedded in the capture itself (its pcapng Decryption Secrets
// Block) can then decrypt it.
func TsharkArgs(pcapPath, keylogPath string) []string {
	return []string{"-r", pcapPath, "-o", "tls.keylog_file:" + keylogPath}
}

// reassembleOutOfOrder makes tshark reassemble TCP segments that arrive out
// of sequence instead of abandoning the stream at the first gap. Wireshark
// ships this off by default purely as a performance/memory trade-off for live
// dissection, but a real capture of a container's egress routinely records
// segments out of order -- measured here on a rootful Podman pod, roughly a
// third of otherwise-perfect TLS 1.3 sessions arrive with the server's
// segments jumbled (confirmed via IP IDs: the server sent them in order).
// Without this, TLS record reassembly abandons such a session and it decrypts
// to nothing, which looks exactly like packet loss or a bad key. It is not a
// defect of the in-process capture: an independent, simultaneous capture of
// the same sessions through an mmap'd AF_PACKET ring buffer recorded the same
// reordering, and needed the same option to decrypt them.
const reassembleOutOfOrder = "tcp.reassemble_out_of_order:TRUE"

// DecryptedAppData runs tshark over pcapPath paired with keylogPath (see
// TsharkArgs for an empty keylogPath), applying the given display filter
// (e.g. AppDataFilter), and returns tshark's decoded output. This automates:
// tshark -r <pcap> -o "tls.keylog_file:<keylog>" -o tcp.reassemble_out_of_order:TRUE -Y <filter> -V.
// -V (full protocol detail) is required, not just -Y: tshark's default
// one-line summary per matched packet never includes the actual decrypted
// payload (e.g. an HTTP response body), only protocol/field summaries -- so
// without it this would never satisfy "yield the request's plaintext HTTP"
// (CAPTURE-04/CAPTURE-11). -x (hex+ASCII dump) was considered instead but
// rejected: it hard-wraps at a fixed 16 bytes/line, which can split a
// plaintext string's ASCII representation across two lines depending on its
// byte offset, making it unreliable for substring matching on the result.
//
// ctx bounds the run: tshark is killed once ctx is done, and the returned
// error then reports ctx's cause rather than the kill signal. A failed run's
// error carries tshark's stderr, which names the actual problem (an invalid
// filter, an unreadable capture).
func DecryptedAppData(ctx context.Context, pcapPath, keylogPath, filter string) (string, error) {
	args := append(TsharkArgs(pcapPath, keylogPath), "-o", reassembleOutOfOrder, "-Y", filter, "-V")
	out, err := exec.CommandContext(ctx, "tshark", args...).Output() // #nosec G204 -- test-supplied paths/filter, passed as argv with no shell
	if err == nil {
		return string(out), nil
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("capturetest: run tshark: %w", context.Cause(ctx))
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return "", fmt.Errorf("capturetest: run tshark: %w: %s", err, bytes.TrimSpace(exitErr.Stderr))
	}
	return "", fmt.Errorf("capturetest: run tshark: %w", err)
}
