package keylog

import (
	"errors"
	"fmt"
	"os"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// defaultUprobeSymbol is the exported libssl entry point the uprobe attaches
// to; see bpf/tls_keylog.bpf.c for why an exported symbol is required on
// production (stripped) libssl builds.
const defaultUprobeSymbol = "SSL_write"

// ConsumerConfig configures uprobe attach and ring-buffer consumption for one
// target process.
type ConsumerConfig struct {
	// PID is the target application's process ID.
	PID int
	// LibsslOverride is the --libssl flag; empty triggers discovery.
	LibsslOverride string
	// Symbol overrides the uprobe attach point; defaults to "SSL_write".
	Symbol string
	// PinDir is the bpffs directory for the pinned config/ring-buffer maps.
	PinDir string
	// Layout supplies the client_random/secret offsets and labels to read.
	Layout Layout
	// TLSVersion is the negotiated version tag written to every event
	// (bpf/tls_keylog.bpf.c's `tls_config.tls_version`).
	TLSVersion uint16
	// KeylogPath is where validated, deduplicated NSS lines are appended.
	KeylogPath string
}

// Consumer attaches the tls_keylog uprobe to a resolved library, reads secret
// events from the ring buffer, and routes them through the classifier,
// formatter, and writer into the NSS keylog.
type Consumer struct {
	objs   bpf.TlsKeylogObjects
	link   link.Link
	reader *ringbuf.Reader
	writer *Writer
	pinDir string
}

// ErrNoSecretsConfigured is returned when the given Layout has no secrets to
// read (nothing to attach for).
var ErrNoSecretsConfigured = errors.New("keylog: layout has no secrets configured")

// NewConsumer resolves the target's libssl, attaches the uprobe, and opens
// the ring-buffer reader and keylog writer. Call Run to start consuming and
// Close to release everything.
func NewConsumer(cfg ConsumerConfig) (*Consumer, error) {
	if len(cfg.Layout.Secrets) == 0 {
		return nil, ErrNoSecretsConfigured
	}
	if len(cfg.Layout.Secrets) > 8 {
		return nil, fmt.Errorf("keylog: layout has %d secrets, max 8", len(cfg.Layout.Secrets))
	}

	symbol := cfg.Symbol
	if symbol == "" {
		symbol = defaultUprobeSymbol
	}

	libPath, err := ResolveLibssl(DiscoveryConfig{PID: cfg.PID, Override: cfg.LibsslOverride})
	if err != nil {
		return nil, fmt.Errorf("keylog: resolve libssl: %w", err)
	}
	if _, err := AttachSpec(libPath, []string{symbol}); err != nil {
		return nil, fmt.Errorf("keylog: uprobe target: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("keylog: remove memlock: %w", err)
	}
	if err := os.MkdirAll(cfg.PinDir, 0o700); err != nil {
		return nil, fmt.Errorf("keylog: create pin dir: %w", err)
	}

	var objs bpf.TlsKeylogObjects
	if err := bpf.LoadTlsKeylogObjects(&objs, &ciliumebpf.CollectionOptions{
		Maps: ciliumebpf.MapOptions{PinPath: cfg.PinDir},
	}); err != nil {
		return nil, fmt.Errorf("keylog: load objects: %w", err)
	}

	if err := writeTLSConfig(&objs, cfg); err != nil {
		_ = objs.Close()
		return nil, err
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("keylog: open executable %q: %w", libPath, err)
	}
	up, err := ex.Uprobe(symbol, objs.UprobeTlsKeylog, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("keylog: attach uprobe %s: %w", symbol, err)
	}

	reader, err := ringbuf.NewReader(objs.SecretsRb)
	if err != nil {
		_ = up.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("keylog: open ring buffer: %w", err)
	}

	w, err := NewWriter(cfg.KeylogPath)
	if err != nil {
		_ = reader.Close()
		_ = up.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("keylog: open writer: %w", err)
	}

	return &Consumer{objs: objs, link: up, reader: reader, writer: w, pinDir: cfg.PinDir}, nil
}

// writeTLSConfig populates the single-entry `config` map the uprobe reads.
func writeTLSConfig(objs *bpf.TlsKeylogObjects, cfg ConsumerConfig) error {
	tc := bpf.TlsKeylogTlsConfig{
		TargetPid:       uint32(cfg.PID), // #nosec G115 -- PIDs fit in uint32 on Linux
		ClientRandomOff: cfg.Layout.ClientRandomOffset,
		SecretCount:     uint32(len(cfg.Layout.Secrets)), // #nosec G115 -- bounded to <=8 by the check above
		TlsVersion:      cfg.TLSVersion,
	}
	for i, s := range cfg.Layout.Secrets {
		tc.SecretOff[i] = s.Offset
		tc.SecretLen[i] = s.Len
		label, ok := labelByName[s.Label]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownLabel, s.Label)
		}
		tc.SecretLabel[i] = uint16(label)
	}
	var zero uint32
	return objs.TlsKeylogConfig.Update(&zero, &tc, ciliumebpf.UpdateAny)
}

// RouteEvent decodes, classifies, formats, and writes one raw ring-buffer
// record. Events for an unknown label or malformed content are dropped
// (never emitted as a spurious/garbage keylog line).
func RouteEvent(raw []byte, w *Writer) error {
	ev, err := DecodeEvent(raw)
	if err != nil {
		return err
	}
	line, err := FormatLine(ev.Label, ev.ClientRandom[:], ev.Secret[:ev.SecretLen])
	if err != nil {
		return err
	}
	return w.Append(line)
}

// Run consumes ring-buffer records until the reader is closed (via Close) or
// a read error occurs. Per-record errors (malformed/unknown events) are
// swallowed so one bad record never stops the consumer.
func (c *Consumer) Run() error {
	for {
		rec, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		_ = RouteEvent(rec.RawSample, c.writer)
	}
}

// Close detaches the uprobe, closes the ring-buffer reader/objects/writer,
// and removes the pinned maps.
func (c *Consumer) Close() error {
	var errs []error
	if err := c.reader.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.link.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := c.writer.Close(); err != nil {
		errs = append(errs, err)
	}
	if c.pinDir != "" {
		if err := os.RemoveAll(c.pinDir); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
