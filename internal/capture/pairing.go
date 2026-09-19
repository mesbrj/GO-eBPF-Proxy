package capture

import (
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
func TsharkArgs(pcapPath, keylogPath string) []string {
	return []string{"-r", pcapPath, "-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath)}
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
// capture-backend defect: a simultaneous tcpdump -- an mmap'd AF_PACKET ring
// buffer, the very thing a gopacket/afpacket migration would provide --
// records the same reordering on the same sessions, and needs the same option
// to decrypt them.
const reassembleOutOfOrder = "tcp.reassemble_out_of_order:TRUE"

// DecryptedAppData runs tshark over pcapPath paired with keylogPath, applying
// the given display filter (e.g. AppDataFilter), and returns tshark's decoded
// output. This automates:
// tshark -r <pcap> -o "tls.keylog_file:<keylog>" -o tcp.reassemble_out_of_order:TRUE -Y <filter> -V.
// -V (full protocol detail) is required, not just -Y: tshark's default
// one-line summary per matched packet never includes the actual decrypted
// payload (e.g. an HTTP response body), only protocol/field summaries -- so
// without it this would never satisfy "yield the request's plaintext HTTP"
// (CAPTURE-04/CAPTURE-11). -x (hex+ASCII dump) was considered instead but
// rejected: it hard-wraps at a fixed 16 bytes/line, which can split a
// plaintext string's ASCII representation across two lines depending on its
// byte offset, making it unreliable for substring matching on the result.
func DecryptedAppData(pcapPath, keylogPath, filter string) (string, error) {
	args := append(TsharkArgs(pcapPath, keylogPath), "-o", reassembleOutOfOrder, "-Y", filter, "-V")
	out, err := exec.Command("tshark", args...).Output() // #nosec G204 -- paths/filter are operator-supplied config, not raw user input
	if err != nil {
		return "", fmt.Errorf("capture: run tshark: %w", err)
	}
	return string(out), nil
}
