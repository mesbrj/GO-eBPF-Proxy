// Package keylog extracts TLS session secrets from the app's TLS library via
// eBPF uprobes and writes them as an NSS-format keylog. No TLS termination, no
// MITM, no CA: the app's handshake stays end-to-end with the real server.
package keylog

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ErrLibraryNotFound is returned when libssl/libcrypto cannot be resolved for
// the target process by any discovery strategy.
var ErrLibraryNotFound = errors.New("keylog: target library not found")

// ErrSymbolNotFound is returned when a required uprobe symbol is absent from
// the resolved library's ELF symbol table.
var ErrSymbolNotFound = errors.New("keylog: uprobe symbol not found in library")

// DiscoveryConfig configures library resolution for a target process.
type DiscoveryConfig struct {
	// PID is the target application's process ID.
	PID int
	// Override, when non-empty, is used verbatim (the --libssl flag).
	Override string
	// ProcRoot defaults to "/proc"; overridable in tests.
	ProcRoot string
	// ListDynamicLibraries defaults to running `ldconfig -p`; overridable in
	// tests to avoid depending on the host's ld.so.cache contents.
	ListDynamicLibraries func() ([]byte, error)
}

// procRoot returns the configured proc root, defaulting to "/proc".
func (c DiscoveryConfig) procRoot() string {
	if c.ProcRoot != "" {
		return c.ProcRoot
	}
	return "/proc"
}

// lister returns the configured ld.so.cache lister, defaulting to `ldconfig -p`.
func (c DiscoveryConfig) lister() func() ([]byte, error) {
	if c.ListDynamicLibraries != nil {
		return c.ListDynamicLibraries
	}
	return func() ([]byte, error) { return exec.Command("ldconfig", "-p").Output() }
}

// ResolveLibssl resolves the path to the target's libssl (or its executable,
// for a statically linked binary). Resolution order: --libssl override,
// /proc/<pid>/maps, ld.so.cache (via `ldconfig -p`), then the executable path.
func ResolveLibssl(cfg DiscoveryConfig) (string, error) {
	return resolveLibrary(cfg, "libssl.so")
}

// ResolveLibcrypto resolves the path to the target's libcrypto, following the
// same strategy as ResolveLibssl.
func ResolveLibcrypto(cfg DiscoveryConfig) (string, error) {
	return resolveLibrary(cfg, "libcrypto.so")
}

func resolveLibrary(cfg DiscoveryConfig, soName string) (string, error) {
	if cfg.Override != "" {
		if _, err := os.Stat(cfg.Override); err != nil {
			return "", fmt.Errorf("keylog: --libssl override %q: %w", cfg.Override, err)
		}
		return cfg.Override, nil
	}

	mapsPath := filepath.Join(cfg.procRoot(), strconv.Itoa(cfg.PID), "maps")
	if path, err := scanMaps(mapsPath, soName); err == nil {
		return path, nil
	}

	if path, err := scanLdConfig(cfg.lister(), soName); err == nil {
		return path, nil
	}

	// Statically linked binary: target the executable itself.
	exePath := filepath.Join(cfg.procRoot(), strconv.Itoa(cfg.PID), "exe")
	if _, err := os.Lstat(exePath); err == nil {
		return exePath, nil
	}

	return "", ErrLibraryNotFound
}

// scanMaps looks for a mapped library whose basename starts with soName in a
// /proc/<pid>/maps-formatted file.
func scanMaps(mapsPath, soName string) (string, error) {
	f, err := os.Open(mapsPath) // #nosec G304 -- mapsPath is built from a controlled proc root + pid, not raw user input
	if err != nil {
		return "", ErrLibraryNotFound
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := fields[len(fields)-1]
		if strings.HasPrefix(filepath.Base(path), soName) {
			return path, nil
		}
	}
	return "", ErrLibraryNotFound
}

// ldConfigLineRE matches an `ldconfig -p` entry, e.g.:
//
//	libssl.so.3 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.3
var ldConfigLineRE = regexp.MustCompile(`^\s*(\S+)\s+\([^)]*\)\s*=>\s*(\S+)\s*$`)

// scanLdConfig looks for soName among the entries listed by the given lister
// (normally `ldconfig -p`, i.e. /etc/ld.so.cache).
func scanLdConfig(lister func() ([]byte, error), soName string) (string, error) {
	out, err := lister()
	if err != nil {
		return "", ErrLibraryNotFound
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		m := ldConfigLineRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if strings.HasPrefix(m[1], soName) {
			return m[2], nil
		}
	}
	return "", ErrLibraryNotFound
}

// UprobeTarget is a resolved (library, symbol) attach point for a uprobe.
type UprobeTarget struct {
	Library string
	Symbol  string
}

// AttachSpec builds the uprobe attach targets for the given symbols against
// the resolved library path, verifying each symbol is present in the ELF
// symbol table (dynamic or static). Returns ErrSymbolNotFound for any symbol
// missing from the binary.
func AttachSpec(path string, symbols []string) ([]UprobeTarget, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keylog: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	present := make(map[string]struct{})
	for _, syms := range [][]elf.Symbol{mustSymbols(f.DynamicSymbols), mustSymbols(f.Symbols)} {
		for _, s := range syms {
			present[s.Name] = struct{}{}
		}
	}

	targets := make([]UprobeTarget, 0, len(symbols))
	for _, sym := range symbols {
		if _, ok := present[sym]; !ok {
			return nil, fmt.Errorf("%w: %s in %s", ErrSymbolNotFound, sym, path)
		}
		targets = append(targets, UprobeTarget{Library: path, Symbol: sym})
	}
	return targets, nil
}

// mustSymbols swallows the error from an ELF symbol-table reader (e.g. a
// stripped binary has no .symtab); an empty table is a valid result here.
func mustSymbols(read func() ([]elf.Symbol, error)) []elf.Symbol {
	syms, err := read()
	if err != nil {
		return nil
	}
	return syms
}
