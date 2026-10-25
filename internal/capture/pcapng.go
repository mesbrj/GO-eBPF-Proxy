package capture

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// Room is the most bytes the capture file may reach, its header
	// included. Every packet and keylog line is counted when it is handed
	// over, so the hold queue and pending secrets count as written. The
	// first one that does not fit in what is left stops capture for good:
	// neither it nor anything after it is written (AD-020). Zero, the
	// default, sets no limit. A Room below HeaderSize stops capture at the
	// first block; the sidecar never starts a capture with one.
	Room int64
	// OnStop, if set, is called once, when capture stops at Room. It runs on
	// the goroutine whose packet or line did not fit, outside the Writer's
	// lock.
	OnStop func(Stop)
}

// Stop describes a capture that stopped at its room.
type Stop struct {
	// Path is the capture file.
	Path string
	// Bytes is what the file reaches once everything admitted before the
	// stop is written, header included. Each keylog line is counted as a
	// Decryption Secrets Block of its own, so this is an upper bound.
	Bytes int64
	// Room is the room capture stopped at.
	Room int64
}

// State is where a run's capture stands (door 4).
type State int

const (
	// StateActive is a capture that is running.
	StateActive State = iota
	// StateStoppedMaxBytes is a capture that stopped at --max-bytes during
	// the run.
	StateStoppedMaxBytes
	// StateNotStartedMaxBytes is a run that started no capture, because
	// --max-bytes was already reached when it started.
	StateNotStartedMaxBytes
)

// String returns the state as the sidecar's stats line reports it.
func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateStoppedMaxBytes:
		return "stopped_max_bytes"
	case StateNotStartedMaxBytes:
		return "not_started_max_bytes"
	default:
		return "State(" + strconv.Itoa(int(s)) + ")"
	}
}

// ErrStopped is what WritePacket returns for the packet that stopped capture
// at its room and for every packet after it. None of them is written.
var ErrStopped = errors.New("capture: stopped at its size limit")

func (o Options) linkType() layers.LinkType {
	if o.LinkType == 0 {
		return layers.LinkTypeEthernet
	}
	return o.LinkType
}

// HeaderSize returns the bytes a Writer made with opts writes before its
// first packet or secret: its Section Header and Interface Description
// Blocks. A capture needs at least this much room (AC 11).
func HeaderSize(opts Options) int64 {
	var buf bytes.Buffer
	ng, _ := pcapgo.NewNgWriter(&buf, opts.linkType()) // writing to memory cannot fail
	_ = ng.Flush()
	return int64(buf.Len())
}

// epbSize is the size of the Enhanced Packet Block pcapgo writes for n bytes
// of packet data, with no options.
func epbSize(n int) int64 { return 32 + pad4(n) }

// dsbSize is the size of a Decryption Secrets Block whose payload is n bytes.
func dsbSize(n int) int64 { return 20 + pad4(n) }

// pad4 rounds n up to the 4-byte boundary pcapng pads block bodies to.
func pad4(n int) int64 { return (int64(n) + 3) &^ 3 }

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

// Writer is an in-process pcapng (SHB/IDB/EPB) writer for the captured traffic
// that keeps the capture self-decrypting while it is being written: packets
// wait out holdWindow, and each NSS keylog line handed to AddSecret is
// written as a TLS Decryption Secrets Block ahead of every packet still held
// (AD-018). Close drains what is still held and closes the file without
// rewriting it, so the closed capture keeps that live layout (AD-022). With a
// room set (Options.Room), it stops capture before the file would pass it
// (AD-020). Its methods are safe for concurrent use.
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

	// limited is false when Options.Room set no limit. room is the current
	// room, admitted the bytes counted against it so far, header included.
	limited  bool
	room     int64
	admitted int64
	onStop   func(Stop)
	// stopped is set once, under mu, when a block does not fit the room. It
	// is read without the lock by State.
	stopped atomic.Bool
	// closed is set once the file is closed: by Close, or by the drain once
	// it has written everything admitted before a stop. closeErr is what the
	// drain's close returned.
	closed   bool
	closeErr error

	stop     chan struct{}
	stopOnce sync.Once
	drained  chan struct{} // closed once the periodic drain has exited
}

// maxRunSuffix is the highest suffix CreateRunCapture tries when the names
// before it are taken.
const maxRunSuffix = 999

// CreateRunCapture creates this run's capture file from template, the
// --capture-path (AD-021, door 1): <dir>/<stem>-<start second><ext>, where
// <dir>, <stem> and <ext> come from template and the start second is
// opts.Clock's, in Unix seconds. When that name is taken, by any kind of
// entry, a dangling symlink included, it creates <stem>-<epoch>-<n><ext> for
// the lowest free n from 1 to 999. Every name is created by NewWriter with
// O_CREAT|O_EXCL rather than checked first, so an entry already there is
// never followed, truncated or overwritten. Any other error fails, and so do
// 999 taken suffixes.
func CreateRunCapture(template string, opts Options) (*Writer, error) {
	clock := opts.Clock
	if clock == nil {
		clock = SystemClock{}
	}
	dir, stem, ext := splitTemplate(template)
	base := filepath.Join(dir, stem+"-"+strconv.FormatInt(clock.Now().Unix(), 10))
	for n := 0; n <= maxRunSuffix; n++ {
		path := base + ext
		if n > 0 {
			path = base + "-" + strconv.Itoa(n) + ext
		}
		w, err := NewWriter(path, opts)
		if !errors.Is(err, fs.ErrExist) {
			return w, err
		}
	}
	return nil, fmt.Errorf("capture: no free capture name in %q: %s%s and its suffixes 1 to %d are all taken", dir, filepath.Base(base), ext, maxRunSuffix)
}

// splitTemplate splits a --capture-path into the directory, stem and
// extension every run's capture name is built from.
func splitTemplate(template string) (dir, stem, ext string) {
	base := filepath.Base(template)
	ext = filepath.Ext(base)
	return filepath.Dir(template), strings.TrimSuffix(base, ext), ext
}

// NewWriter creates the pcapng file at path, which must not exist yet,
// creating its parent directory 0700 and the file 0600 -- secret-grade like
// the keylog file (AD-006), since the DSBs make the capture itself a secret
// -- writes the initial Section Header + Interface Block, and starts
// draining the hold queue every flushInterval until Close. An entry already
// at path fails it with an error wrapping fs.ErrExist: a capture is never
// truncated or overwritten (AD-021).
func NewWriter(path string, opts Options) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("capture: create capture dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304,G302 -- path is operator-supplied config, not raw user input; 0600 is the intended secret-grade mode
	if err != nil {
		return nil, fmt.Errorf("capture: open %q: %w", path, err)
	}

	ng, err := pcapgo.NewNgWriter(f, opts.linkType())
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
	w := &Writer{
		f: f, ng: ng, clock: clock, path: path,
		limited: opts.Room > 0, room: opts.Room, admitted: HeaderSize(opts), onStop: opts.OnStop,
		stop: make(chan struct{}), drained: make(chan struct{}),
	}
	go w.drainPeriodically()
	return w, nil
}

// Path returns the capture file's path.
func (w *Writer) Path() string { return w.path }

// State reports StateActive until capture stops at its room, and
// StateStoppedMaxBytes from then on. It takes no lock.
func (w *Writer) State() State {
	if w.stopped.Load() {
		return StateStoppedMaxBytes
	}
	return StateActive
}

// SetRoom changes the room of a Writer created with one: the sidecar grows it
// after its age pass deletes captures (AC 8). A room at or below what was
// already admitted admits nothing more. It is ignored by a Writer created
// without a room, and has no effect once capture has stopped, which is for
// good (AC 9).
func (w *Writer) SetRoom(room int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limited {
		w.room = room
	}
}

// admit counts a block of n bytes against the room and reports whether it
// may be written. The first block that does not fit stops capture, and no
// block is admitted after it; for that first one only, admit also returns
// the Stop for the caller to notify once it has released w.mu. w.mu must be
// held.
func (w *Writer) admit(n int64) (bool, *Stop) {
	if w.stopped.Load() {
		return false, nil
	}
	if w.limited && w.admitted+n > w.room {
		w.stopped.Store(true)
		return false, &Stop{Path: w.path, Bytes: w.admitted, Room: w.room}
	}
	w.admitted += n
	return true, nil
}

// notifyStop hands stop, if any, to Options.OnStop. w.mu must not be held.
func (w *Writer) notifyStop(stop *Stop) {
	if stop != nil && w.onStop != nil {
		w.onStop(*stop)
	}
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
//
// A packet whose block does not fit the room left stops capture: it, and
// every packet after it, returns ErrStopped and is not written.
func (w *Writer) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	w.mu.Lock()
	if ok, stop := w.admit(epbSize(len(data))); !ok {
		w.mu.Unlock()
		w.notifyStop(stop)
		return ErrStopped
	}
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
// sink. An empty line is ignored. A line whose block does not fit the room
// left stops capture, and neither it nor any line after it is written.
func (w *Writer) AddSecret(line string) {
	if line == "" {
		return
	}
	w.mu.Lock()
	ok, stop := w.admit(dsbSize(len(line) + 1))
	if ok {
		w.pending = append(w.pending, line)
	}
	w.mu.Unlock()
	w.notifyStop(stop)
}

// drainPeriodically drains the hold queue every flushInterval until Close,
// or until capture has stopped and everything admitted before the stop is
// written: it then closes the file, which nothing will be added to again.
func (w *Writer) drainPeriodically() {
	defer close(w.drained)
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			w.mu.Lock()
			_ = w.drain() // a packet that fails to write is dropped, not fatal, as capture.Live does
			if w.stopped.Load() && len(w.held) == 0 && len(w.pending) == 0 {
				w.closeErr, w.closed = w.closeFile(), true
			}
			closed := w.closed
			w.mu.Unlock()
			if closed {
				return
			}
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
// complete only once Close has returned. A capture that stopped at its room
// and was already closed by the drain only reports how that close went.
func (w *Writer) Close() error {
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.drained

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	_ = w.writeHeld(len(w.held)) // a packet that fails to write is dropped, as in drain
	return w.closeFile()
}

// closeFile flushes and closes the file. w.mu must be held.
func (w *Writer) closeFile() error {
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
