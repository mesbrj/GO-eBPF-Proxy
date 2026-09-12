package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Options configures a Writer.
type Options struct {
	// LinkType is the datalink layer of captured packets. Zero (the Go zero
	// value) defaults to Ethernet, the link type of the captured eth0 leg.
	LinkType layers.LinkType
	// Clock timestamps packets whose CaptureInfo.Timestamp is zero, so
	// capture shares one time source with any paired component (CAPTURE-02).
	// Defaults to SystemClock.
	Clock Clock
}

// Writer is an in-process pcapng (SHB/IDB/EPB) writer for the outbound leg,
// with support for embedding the NSS keylog as a Decryption Secrets Block.
type Writer struct {
	f     *os.File
	ng    *pcapgo.NgWriter
	clock Clock
}

// NewWriter creates (or truncates) the pcapng file at path, creating its
// parent directory 0700 and the file 0600 -- secret-grade like the keylog
// file (AD-006), since an embedded DSB makes the capture itself a secret --
// and writes the initial Section Header + Interface Block.
func NewWriter(path string, opts Options) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("capture: create capture dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304,G302 -- path is operator-supplied config, not raw user input; 0600 is the intended secret-grade mode
	if err != nil {
		return nil, fmt.Errorf("capture: open %q: %w", path, err)
	}

	linkType := opts.LinkType
	if linkType == 0 {
		linkType = layers.LinkTypeEthernet
	}
	ng, err := pcapgo.NewNgWriter(f, linkType)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("capture: create pcapng writer: %w", err)
	}

	clock := opts.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	return &Writer{f: f, ng: ng, clock: clock}, nil
}

// WritePacket appends one packet as an Enhanced Packet Block. A zero
// ci.Timestamp is stamped from the Writer's Clock so every packet carries a
// timestamp from the single shared source.
func (w *Writer) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if ci.Timestamp.IsZero() {
		ci.Timestamp = w.clock.Now()
	}
	if ci.CaptureLength == 0 {
		ci.CaptureLength = len(data)
	}
	if ci.Length == 0 {
		ci.Length = len(data)
	}
	return w.ng.WritePacket(ci, data)
}

// EmbedKeylog writes lines -- already-validated NSS keylog lines -- as a
// single TLS Decryption Secrets Block, so tshark/Wireshark decrypt the
// capture without pairing a separate keylog file. A nil/empty lines is a
// no-op: there is nothing to embed.
func (w *Writer) EmbedKeylog(lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	payload := []byte(strings.Join(lines, "\n") + "\n")
	return w.ng.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, payload)
}

// Close flushes buffered blocks and closes the underlying file. The
// pcapgo.NgWriter buffers internally, so Close must be called before the
// file is considered complete.
func (w *Writer) Close() error {
	if err := w.ng.Flush(); err != nil {
		_ = w.f.Close()
		return fmt.Errorf("capture: flush pcapng: %w", err)
	}
	return w.f.Close()
}
