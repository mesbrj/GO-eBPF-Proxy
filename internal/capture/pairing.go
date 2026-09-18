package capture

import (
	"fmt"
	"os/exec"
)

// TsharkArgs returns the tshark arguments that pair a capture file with its
// NSS keylog for offline decryption: tshark -r <pcap> -o "tls.keylog_file:<keylog>".
func TsharkArgs(pcapPath, keylogPath string) []string {
	return []string{"-r", pcapPath, "-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath)}
}

// DecryptedAppData runs tshark over pcapPath paired with keylogPath, applying
// the given display filter (e.g. "http"), and returns tshark's decoded
// output. This automates:
// tshark -r <pcap> -o "tls.keylog_file:<keylog>" -Y <filter> -V.
// -V (full protocol detail) is required, not just -Y: tshark's default
// one-line summary per matched packet never includes the actual decrypted
// payload (e.g. an HTTP response body), only protocol/field summaries -- so
// without it this would never satisfy "yield the request's plaintext HTTP"
// (CAPTURE-04/CAPTURE-11). -x (hex+ASCII dump) was considered instead but
// rejected: it hard-wraps at a fixed 16 bytes/line, which can split a
// plaintext string's ASCII representation across two lines depending on its
// byte offset, making it unreliable for substring matching on the result.
func DecryptedAppData(pcapPath, keylogPath, filter string) (string, error) {
	args := append(TsharkArgs(pcapPath, keylogPath), "-Y", filter, "-V")
	out, err := exec.Command("tshark", args...).Output() // #nosec G204 -- paths/filter are operator-supplied config, not raw user input
	if err != nil {
		return "", fmt.Errorf("capture: run tshark: %w", err)
	}
	return string(out), nil
}
