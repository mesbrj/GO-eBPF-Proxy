package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// Compiled-in constants; these MUST match bpf/proxy.bpf.c.
const (
	// ProxyUID is the sidecar UID skipped by connect4 (loop avoidance).
	ProxyUID uint32 = 1337
	// ProxyPort is the local relay port destinations are rewritten to.
	ProxyPort uint16 = 15001
	// DefaultPinDir is the bpffs directory where maps are pinned.
	DefaultPinDir = "/sys/fs/bpf/go-ebpf-proxy"

	bpffsPrefix = "/sys/fs/bpf"
)

// Config configures the loader.
type Config struct {
	// CgroupPath is the pod common-parent cgroup v2 directory to attach to.
	CgroupPath string
	// PinDir is a bpffs directory for the pinned maps.
	PinDir string
	// ProxyUID / ProxyPort mirror the compiled-in constants (validated).
	ProxyUID  uint32
	ProxyPort uint16
}

// DefaultConfig returns a Config populated with the compiled-in constants.
// The caller must set CgroupPath.
func DefaultConfig() Config {
	return Config{PinDir: DefaultPinDir, ProxyUID: ProxyUID, ProxyPort: ProxyPort}
}

// Validate rejects unsafe or inconsistent configuration.
func (c Config) Validate() error {
	if c.CgroupPath == "" {
		return errors.New("ebpf: CgroupPath must be set")
	}
	clean := filepath.Clean(c.PinDir)
	if clean != bpffsPrefix && !strings.HasPrefix(clean, bpffsPrefix+"/") {
		return fmt.Errorf("ebpf: PinDir %q must be under %s", c.PinDir, bpffsPrefix)
	}
	if c.ProxyUID == 0 {
		return errors.New("ebpf: ProxyUID must not be 0 (root)")
	}
	if c.ProxyPort == 0 {
		return errors.New("ebpf: ProxyPort must be a valid non-zero port")
	}
	return nil
}

// Loader owns the loaded objects, cgroup links, and pins.
type Loader struct {
	objs   bpf.ProxyObjects
	links  []link.Link
	pinDir string
}

// Load loads and pins the eBPF objects. It does not attach; call Attach next.
func Load(cfg Config) (*Loader, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}
	if err := os.MkdirAll(cfg.PinDir, 0o700); err != nil {
		return nil, fmt.Errorf("ebpf: create pin dir: %w", err)
	}
	var objs bpf.ProxyObjects
	if err := bpf.LoadProxyObjects(&objs, &ciliumebpf.CollectionOptions{
		Maps: ciliumebpf.MapOptions{PinPath: cfg.PinDir},
	}); err != nil {
		return nil, fmt.Errorf("ebpf: load objects: %w", err)
	}
	return &Loader{objs: objs, pinDir: cfg.PinDir}, nil
}

// Attach binds connect4 and sockops to the given cgroup v2 path.
func (l *Loader) Attach(cgroupPath string) error {
	c4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ciliumebpf.AttachCGroupInet4Connect,
		Program: l.objs.CgroupConnect4,
	})
	if err != nil {
		return fmt.Errorf("ebpf: attach connect4: %w", err)
	}
	l.links = append(l.links, c4)

	so, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ciliumebpf.AttachCGroupSockOps,
		Program: l.objs.SockopsProg,
	})
	if err != nil {
		return fmt.Errorf("ebpf: attach sockops: %w", err)
	}
	l.links = append(l.links, so)
	return nil
}

// OrigDstByTuple returns the tuple map the relay reads for original-dst lookup.
func (l *Loader) OrigDstByTuple() *ciliumebpf.Map {
	return l.objs.OrigdstByTuple
}

// Close detaches the programs, closes the objects, and removes the pins.
func (l *Loader) Close() error {
	var errs []error
	for _, lk := range l.links {
		if err := lk.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	l.links = nil
	if err := l.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if l.pinDir != "" {
		if err := os.RemoveAll(l.pinDir); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
