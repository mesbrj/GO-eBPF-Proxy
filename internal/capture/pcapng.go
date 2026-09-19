package capture

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// MaxCaptureLength is the AF_PACKET read-buffer size callers should pass to
// (*pcapgo.EthernetHandle).SetCaptureLength for a live interface capture.
// pcapgo.NewEthernetHandle defaults that buffer to the interface's MTU
// (typically 1500 for eth0), but GSO/TSO-enabled container network
// interfaces (veth, as used by Podman) can deliver a single AF_PACKET frame
// far larger than the physical MTU before real on-wire segmentation --
// anything over the MTU then gets silently truncated (tshark shows
// "[Packet size limited during capture]"), which breaks TLS record
// reconstruction and offline decryption (CAPTURE-01/CAPTURE-04/CAPTURE-11).
// 65536 comfortably covers the Linux GSO maximum.
const MaxCaptureLength = 65536

// flushInterval bounds how stale an on-disk capture can be while packets are
// still arriving: WritePacket flushes at most this often (plus always on the
// very first packet), rather than after every single packet. Flushing every
// packet is a real write(2) syscall per packet, which cannot keep up with a
// bursty flow (e.g. a TLS handshake's back-to-back segments) and causes the
// kernel to drop packets from the AF_PACKET socket's receive queue while the
// capture goroutine is blocked flushing -- corrupting TLS record
// reconstruction just as badly as the truncation MaxCaptureLength fixes.
const flushInterval = 200 * time.Millisecond

// Writer is an in-process pcapng (SHB/IDB/EPB) writer for the outbound leg,
// with support for embedding the NSS keylog as a Decryption Secrets Block.
type Writer struct {
	f         *os.File
	ng        *pcapgo.NgWriter
	clock     Clock
	lastFlush time.Time
	// path, linkType and headerLen let Close re-emit the capture with the
	// Decryption Secrets Block ahead of the packet blocks (see EmbedKeylog):
	// headerLen is the byte offset at which the initial SHB/IDB end, i.e.
	// where the packet blocks that have to be copied over begin.
	path      string
	linkType  layers.LinkType
	headerLen int64
	// secrets accumulates the NSS keylog lines EmbedKeylog was given, for
	// emission as a single DSB by Close.
	secrets []string
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
	// Flush the SHB/IDB written by NewNgWriter immediately: without this,
	// the file sits at 0 bytes on disk until the first WritePacket (or
	// Close) even though a valid section/interface header was "written".
	if err := ng.Flush(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("capture: flush initial pcapng headers: %w", err)
	}

	// Record where the SHB/IDB end. Close streams the packet blocks written
	// after them into a re-emitted, secrets-first capture, and must not
	// duplicate the headers it already wrote.
	headerLen, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("capture: locate end of pcapng headers in %q: %w", path, err)
	}

	clock := opts.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	return &Writer{f: f, ng: ng, clock: clock, path: path, linkType: linkType, headerLen: headerLen}, nil
}

// WritePacket appends one packet as an Enhanced Packet Block. A zero
// ci.Timestamp is stamped from the Writer's Clock so every packet carries a
// timestamp from the single shared source. ci.InterfaceIndex is forced to 0
// (the writer's single registered interface): pcapgo.NgWriter treats
// InterfaceIndex as a logical, per-file interface id that must already be
// registered via AddInterface, NOT the OS's real ifindex -- but capture
// sources such as pcapgo.EthernetHandle.ReadPacketData populate
// ci.InterfaceIndex with the OS ifindex (e.g. "lo" is commonly 1, "eth0" is
// commonly 2 in a container netns), which is almost never 0. Left
// unnormalized, every WritePacket call fails with "Can't send statistics for
// non existent interface N; have only 1 interfaces", so the capture ends up
// containing only its SHB/IDB header -- indistinguishable from "empty" to an
// operator. Also flushes (at most every flushInterval, always on the first
// packet): pcapgo.NgWriter buffers internally (bufio, 4KB), so without an
// explicit Flush a live capture's file can sit at 0 bytes on disk for an
// entire session until Close is eventually called -- CAPTURE-01/CAPTURE-11
// require the capture to be readable while the sidecar is still running, not
// only after teardown.
func (w *Writer) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	ci.InterfaceIndex = 0
	if ci.Timestamp.IsZero() {
		ci.Timestamp = w.clock.Now()
	}
	if ci.CaptureLength == 0 {
		ci.CaptureLength = len(data)
	}
	if ci.Length == 0 {
		ci.Length = len(data)
	}
	if err := w.ng.WritePacket(ci, data); err != nil {
		return err
	}
	now := time.Now()
	if !w.lastFlush.IsZero() && now.Sub(w.lastFlush) < flushInterval {
		return nil
	}
	w.lastFlush = now
	return w.ng.Flush()
}

// EmbedKeylog records lines -- already-validated NSS keylog lines -- for
// emission as a single TLS Decryption Secrets Block, so tshark/Wireshark
// decrypt the capture without pairing a separate keylog file. Close emits the
// block, positioned ahead of every packet block: pcapng scopes a DSB to the
// blocks that FOLLOW it, and readers (tshark and Wireshark included) consume
// a capture strictly sequentially, so secrets appended after the encrypted
// packets arrive too late to decrypt any of them -- the capture then decrypts
// to nothing at all even though the keys are demonstrably inside it.
// Repeated calls accumulate into that one block; nil/empty lines add nothing.
func (w *Writer) EmbedKeylog(lines []string) error {
	w.secrets = append(w.secrets, lines...)
	return nil
}

// Close flushes buffered blocks, closes the underlying file and, when
// EmbedKeylog supplied any secrets, re-emits the capture with the Decryption
// Secrets Block ahead of the packet blocks. The pcapgo.NgWriter buffers
// internally, so Close must be called before the file is considered complete.
func (w *Writer) Close() error {
	if err := w.ng.Flush(); err != nil {
		_ = w.f.Close()
		return fmt.Errorf("capture: flush pcapng: %w", err)
	}
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("capture: close %q: %w", w.path, err)
	}
	if len(w.secrets) == 0 {
		return nil
	}
	return w.embedSecrets()
}

// embedSecrets re-emits the capture as SHB -> IDB -> DSB -> packet blocks: it
// writes a fresh header plus the Decryption Secrets Block into a sibling
// temporary file, streams the packet blocks already on disk after it, then
// renames that file over the capture, so a concurrent reader only ever sees
// the old or the new capture, never a half-rewritten one. The packet blocks
// are copied as opaque bytes and never held in memory -- a capture routinely
// outgrows RAM -- which is sound because an Enhanced Packet Block is
// position-independent: it refers to its interface only by the id 0 that the
// re-emitted Interface Description Block registers identically.
func (w *Writer) embedSecrets() error {
	src, err := os.Open(w.path) // #nosec G304 -- the very path this Writer created and just closed, not raw user input
	if err != nil {
		return fmt.Errorf("capture: reopen %q to embed keylog: %w", w.path, err)
	}
	defer func() { _ = src.Close() }()
	if _, err := src.Seek(w.headerLen, io.SeekStart); err != nil {
		return fmt.Errorf("capture: seek past pcapng headers in %q: %w", w.path, err)
	}

	// os.CreateTemp creates 0600, the secret-grade mode the capture itself is
	// held at (AD-006) and the mode the rename carries over to it.
	tmp, err := os.CreateTemp(filepath.Dir(w.path), ".dsb-*.pcapng")
	if err != nil {
		return fmt.Errorf("capture: create temp capture beside %q: %w", w.path, err)
	}
	if err := writeSecretsFirst(tmp, src, w.linkType, w.secrets); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("capture: close temp capture %q: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), w.path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("capture: replace %q with the secrets-first capture: %w", w.path, err)
	}
	return nil
}

// writeSecretsFirst writes a fresh SHB/IDB for linkType to dst, then lines as
// one TLS Decryption Secrets Block, then every packet block read from packets.
func writeSecretsFirst(dst io.Writer, packets io.Reader, linkType layers.LinkType, lines []string) error {
	ng, err := pcapgo.NewNgWriter(dst, linkType)
	if err != nil {
		return fmt.Errorf("capture: re-emit pcapng headers: %w", err)
	}
	payload := []byte(strings.Join(lines, "\n") + "\n")
	if err := ng.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, payload); err != nil {
		return fmt.Errorf("capture: write decryption secrets block: %w", err)
	}
	// Flush before copying: the packet blocks go straight to dst, bypassing
	// the NgWriter's own buffer, so anything still buffered would land after
	// them (exactly the ordering bug this whole path exists to avoid).
	if err := ng.Flush(); err != nil {
		return fmt.Errorf("capture: flush pcapng headers and secrets: %w", err)
	}
	if _, err := io.Copy(dst, packets); err != nil {
		return fmt.Errorf("capture: copy packet blocks: %w", err)
	}
	return nil
}
