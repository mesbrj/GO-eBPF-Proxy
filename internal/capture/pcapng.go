package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	// capture shares one time source with any paired component (CAPTURE-02),
	// and measures how long each packet has been held. Defaults to
	// SystemClock.
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

// flushInterval is how often the Writer drains its hold queue to disk and
// flushes. It runs on a ticker, not on packet arrival: a flush triggered only
// by the next packet left a burst's last packets buffered for as long as the
// interface stayed quiet. Flushing every packet instead is a write(2) syscall
// per packet, which cannot keep up with a bursty flow (e.g. a TLS handshake's
// back-to-back segments) and makes the kernel drop packets from the
// AF_PACKET receive queue (AD-011).
const flushInterval = 200 * time.Millisecond

// holdWindow is how long a captured packet waits before it is written, so
// that TLS secrets arriving after it can still be written ahead of it.
// tshark and Wireshark decrypt a TLS 1.3 session only when its secrets
// precede the session's ServerHello in the file -- secrets placed after it
// decrypt nothing, even in two-pass mode -- yet the client can derive them
// only once it has received that ServerHello, which the capture records
// first. Keys reach the sidecar milliseconds later over the keylog socket, so
// holding packets this long keeps the capture on disk self-decrypting while
// it is written: a sidecar killed before Close still leaves a capture that
// decrypts with no keylog file, missing only the packets still held (AD-018).
const holdWindow = time.Second

// maxHeldBytes caps the packet bytes the hold queue keeps in memory. Past it
// the oldest packets are written at once, before their hold window ends:
// memory stays bounded and nothing is dropped, at the cost of such a burst
// possibly landing ahead of its keys, which Close's re-emission repairs.
const maxHeldBytes = 32 << 20

// ngBlockTypeDSB is the pcapng Decryption Secrets Block type.
const ngBlockTypeDSB = 0x0000000a

// heldPacket is a captured packet waiting out the hold window.
type heldPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
	at   time.Time // when WritePacket received it, by the Writer's Clock
}

// Writer is an in-process pcapng (SHB/IDB/EPB) writer for the outbound leg
// that keeps the capture self-decrypting while it is being written: packets
// wait out holdWindow, and each NSS keylog line handed to AddSecret is
// written as a TLS Decryption Secrets Block ahead of every packet still held
// (AD-018). Close re-emits the capture with all of its secrets in one DSB
// ahead of every packet block (AD-014). Its methods are safe for concurrent
// use.
type Writer struct {
	mu    sync.Mutex
	f     *os.File
	ng    *pcapgo.NgWriter
	clock Clock
	// path, linkType and headerLen let Close re-emit the capture with the
	// Decryption Secrets Block ahead of the packet blocks (see
	// embedSecrets): headerLen is the byte offset at which the initial
	// SHB/IDB end, i.e. where the blocks that have to be copied over begin.
	path      string
	linkType  layers.LinkType
	headerLen int64

	// held is the hold queue, oldest first; heldBytes totals its data.
	held      []heldPacket
	heldBytes int
	// pending are the secrets not yet written to the file; secrets is every
	// distinct secret in arrival order, for Close's single DSB; seen dedups
	// both.
	pending []string
	secrets []string
	seen    map[string]struct{}

	stop     chan struct{}
	stopOnce sync.Once
	drained  chan struct{} // closed once the periodic drain has exited
}

// NewWriter creates (or truncates) the pcapng file at path, creating its
// parent directory 0700 and the file 0600 -- secret-grade like the keylog
// file (AD-006), since the DSBs make the capture itself a secret -- writes
// the initial Section Header + Interface Block, and starts draining the hold
// queue every flushInterval until Close.
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
	// the file sits at 0 bytes on disk until the first drain (or Close) even
	// though a valid section/interface header was "written".
	if err := ng.Flush(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("capture: flush initial pcapng headers: %w", err)
	}

	// Record where the SHB/IDB end. Close streams the blocks written after
	// them into a re-emitted, secrets-first capture, and must not duplicate
	// the headers it already wrote.
	headerLen, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("capture: locate end of pcapng headers in %q: %w", path, err)
	}

	clock := opts.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	w := &Writer{
		f: f, ng: ng, clock: clock, path: path, linkType: linkType, headerLen: headerLen,
		seen: make(map[string]struct{}), stop: make(chan struct{}), drained: make(chan struct{}),
	}
	go w.drainPeriodically()
	return w, nil
}

// WritePacket queues one packet to be written as an Enhanced Packet Block
// once it has been held for holdWindow -- sooner when the queue passes
// maxHeldBytes, and at the latest on Close. It takes ownership of data: the
// slice is kept until the packet is written, so the caller must not modify
// it afterwards (pcapgo.EthernetHandle.ReadPacketData returns a fresh slice
// per packet). A zero ci.Timestamp is stamped from the Writer's Clock so
// every packet carries a timestamp from the single shared source.
// ci.InterfaceIndex is forced to 0 (the writer's single registered
// interface): pcapgo.NgWriter treats InterfaceIndex as a logical, per-file
// interface id that must already be registered via AddInterface, NOT the
// OS's real ifindex -- but capture sources such as
// pcapgo.EthernetHandle.ReadPacketData populate ci.InterfaceIndex with the
// OS ifindex (e.g. "lo" is commonly 1, "eth0" is commonly 2 in a container
// netns), which is almost never 0. Left unnormalized, every packet write
// fails with "Can't send statistics for non existent interface N; have only
// 1 interfaces", so the capture ends up containing only its SHB/IDB header --
// indistinguishable from "empty" to an operator.
func (w *Writer) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.clock.Now()
	ci.InterfaceIndex = 0
	if ci.Timestamp.IsZero() {
		ci.Timestamp = now
	}
	if ci.CaptureLength == 0 {
		ci.CaptureLength = len(data)
	}
	if ci.Length == 0 {
		ci.Length = len(data)
	}
	w.held = append(w.held, heldPacket{ci: ci, data: data, at: now})
	w.heldBytes += len(data)

	n, held := 0, w.heldBytes
	for held > maxHeldBytes {
		held -= len(w.held[n].data)
		n++
	}
	if n == 0 {
		return nil
	}
	return w.writeHeld(n)
}

// AddSecret records one NSS keylog line for the capture. The next drain
// writes it in a TLS Decryption Secrets Block ahead of every packet still
// held, and Close embeds it in the capture's single leading DSB. An empty or
// already added line is ignored.
func (w *Writer) AddSecret(line string) {
	if line == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, dup := w.seen[line]; dup {
		return
	}
	w.seen[line] = struct{}{}
	w.pending = append(w.pending, line)
	w.secrets = append(w.secrets, line)
}

// EmbedKeylog adds each of lines -- already-validated NSS keylog lines -- as
// AddSecret does, so tshark/Wireshark decrypt the capture without pairing a
// separate keylog file. Lines already added are ignored; nil/empty lines add
// nothing.
func (w *Writer) EmbedKeylog(lines []string) error {
	for _, l := range lines {
		w.AddSecret(l)
	}
	return nil
}

// drainPeriodically drains the hold queue every flushInterval until Close.
func (w *Writer) drainPeriodically() {
	defer close(w.drained)
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			w.mu.Lock()
			_ = w.drain() // a packet that fails to write is dropped, not fatal, as capture.Live does
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

// drain writes the pending secrets and every packet held for at least
// holdWindow, then flushes. w.mu must be held.
func (w *Writer) drain() error {
	cutoff := w.clock.Now().Add(-holdWindow)
	n := 0
	for n < len(w.held) && !w.held[n].at.After(cutoff) {
		n++
	}
	return errors.Join(w.writeHeld(n), w.ng.Flush())
}

// writeHeld writes the pending secrets as one Decryption Secrets Block, then
// the n oldest held packets. The secrets always go first: every packet still
// held was captured before they arrived, so any of them may be one they
// decrypt. w.mu must be held.
func (w *Writer) writeHeld(n int) error {
	var errs []error
	if len(w.pending) > 0 {
		if err := w.ng.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, secretsPayload(w.pending)); err != nil {
			errs = append(errs, fmt.Errorf("capture: write decryption secrets block: %w", err))
		}
		w.pending = nil
	}
	for _, p := range w.held[:n] {
		if err := w.ng.WritePacket(p.ci, p.data); err != nil {
			errs = append(errs, err)
		}
		w.heldBytes -= len(p.data)
	}
	w.held = slices.Delete(w.held, 0, n)
	return errors.Join(errs...)
}

// Close stops the periodic drain, writes every packet still held (behind any
// pending secrets), closes the underlying file and, when any secrets were
// added, re-emits the capture with all of them in one Decryption Secrets
// Block ahead of the packet blocks. The capture is complete only once Close
// has returned.
func (w *Writer) Close() error {
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.drained

	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.writeHeld(len(w.held)) // a packet that fails to write is dropped, as in drain
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
// re-emitted Interface Description Block registers identically. The live
// DSBs written while capturing are left out: the leading one holds every
// secret they did.
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
// one TLS Decryption Secrets Block, then every block read from blocks except
// its Decryption Secrets Blocks.
func writeSecretsFirst(dst io.Writer, blocks io.Reader, linkType layers.LinkType, lines []string) error {
	ng, err := pcapgo.NewNgWriter(dst, linkType)
	if err != nil {
		return fmt.Errorf("capture: re-emit pcapng headers: %w", err)
	}
	if err := ng.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, secretsPayload(lines)); err != nil {
		return fmt.Errorf("capture: write decryption secrets block: %w", err)
	}
	// Flush before copying: the packet blocks go straight to dst, bypassing
	// the NgWriter's own buffer, so anything still buffered would land after
	// them (exactly the ordering bug this whole path exists to avoid).
	if err := ng.Flush(); err != nil {
		return fmt.Errorf("capture: flush pcapng headers and secrets: %w", err)
	}
	if err := copyBlocksExceptSecrets(dst, blocks); err != nil {
		return fmt.Errorf("capture: copy packet blocks: %w", err)
	}
	return nil
}

// copyBlocksExceptSecrets streams every pcapng block from src to dst as
// opaque bytes, one block at a time, skipping Decryption Secrets Blocks. Each
// block is {type uint32, total length uint32, body, total length uint32},
// little-endian: pcapgo.NgWriter, which wrote every block here, writes no
// other byte order.
func copyBlocksExceptSecrets(dst io.Writer, src io.Reader) error {
	r := bufio.NewReader(src)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		blockType := binary.LittleEndian.Uint32(hdr[0:4])
		rest := int64(binary.LittleEndian.Uint32(hdr[4:8])) - int64(len(hdr))
		if rest < 4 {
			return fmt.Errorf("pcapng block of type %#x declares an impossible length", blockType)
		}
		if blockType == ngBlockTypeDSB {
			if _, err := io.CopyN(io.Discard, r, rest); err != nil {
				return err
			}
			continue
		}
		if _, err := dst.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := io.CopyN(dst, r, rest); err != nil {
			return err
		}
	}
}

// secretsPayload renders lines as a DSB payload: newline-terminated NSS lines.
func secretsPayload(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}
