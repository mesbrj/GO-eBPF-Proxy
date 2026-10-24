package capture

import (
	"errors"
	"fmt"
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
// possibly landing ahead of its keys, where nothing repairs it (AD-022).
const maxHeldBytes = 32 << 20

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
// (AD-018). Close drains what is still held and closes the file without
// rewriting it, so the closed capture keeps that live layout (AD-022). Its
// methods are safe for concurrent use.
type Writer struct {
	mu    sync.Mutex
	f     *os.File
	ng    *pcapgo.NgWriter
	clock Clock
	path  string // names the capture in errors

	// held is the hold queue, oldest first; heldBytes totals its data.
	held      []heldPacket
	heldBytes int
	// pending are the secrets not yet written to the file. A line is kept
	// only until the drain that writes it.
	pending []string

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

	clock := opts.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	w := &Writer{f: f, ng: ng, clock: clock, path: path, stop: make(chan struct{}), drained: make(chan struct{})}
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

// AddSecret records one NSS keylog line for the capture: the next drain (or
// Close) writes it in a TLS Decryption Secrets Block ahead of every packet
// still held. It writes every line it is handed, so the caller hands over
// each line once; the sidecar's keylog.Writer drops duplicates before its
// sink. An empty line is ignored.
func (w *Writer) AddSecret(line string) {
	if line == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, line)
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
// pending secrets), flushes and closes the file. It never reopens, copies or
// rewrites the capture (AD-022): the closed file is the bytes already on disk
// followed by that drained tail, so it needs no disk beyond its own size and
// closes cleanly even once the file has been unlinked. The capture is
// complete only once Close has returned.
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
	return nil
}

// secretsPayload renders lines as a DSB payload: newline-terminated NSS lines.
func secretsPayload(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}
