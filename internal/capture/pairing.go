// Package capture: tshark pairing helper for offline decryption of a
// capture file against its paired NSS keylog.
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
// output. This automates: tshark -r <pcap> -o "tls.keylog_file:<keylog>" -Y <filter>.
func DecryptedAppData(pcapPath, keylogPath, filter string) (string, error) {
	args := append(TsharkArgs(pcapPath, keylogPath), "-Y", filter)
	out, err := exec.Command("tshark", args...).Output() // #nosec G204 -- paths/filter are operator-supplied config, not raw user input
	if err != nil {
		return "", fmt.Errorf("capture: run tshark: %w", err)
	}
	return string(out), nil
}
