package keylog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// GoTLS is an interface-only follow-on module in the MVP (AD-008): OpenSSL is
// the only extraction module with a working uprobe. This file defines the
// discovery/attach contract for a Go binary target so a future Go-ABI-aware
// uprobe can plug in without changing the consumer's shape.
//
// Empirically confirmed on this repo's toolchain (go1.25, amd64): a Go binary
// that performs a TLS handshake retains the ELF symbol
// "crypto/tls.(*Config).writeKeyLog" in its symbol table (not
// "(*Conn).writeKeyLog" as design.md's shorthand suggested) as long as it
// isn't linked with `-ldflags="-s -w"`.
const goTLSWriteKeyLogSymbol = "crypto/tls.(*Config).writeKeyLog"

// ErrGoTLSNotLinked is returned when the target binary has no writeKeyLog
// symbol: it doesn't link crypto/tls, or was built stripped (-s -w).
var ErrGoTLSNotLinked = errors.New("keylog: target binary does not carry crypto/tls's writeKeyLog symbol")

// ErrGoTLSExtractionUnimplemented is returned by Attach: per AD-008, GoTLS is
// an interface-only follow-on in the MVP. Discovery and attach-target
// resolution are implemented and tested; the Go-ABI-aware uprobe that reads
// the label/client_random/secret arguments is not.
var ErrGoTLSExtractionUnimplemented = errors.New("keylog: gotls module is interface-only in the MVP (AD-008); extraction uprobe not implemented")

// ResolveGoBinary resolves the target process's own executable (Go binaries
// are hooked directly; there is no shared library to discover).
func ResolveGoBinary(cfg DiscoveryConfig) (string, error) {
	if cfg.Override != "" {
		if _, err := os.Stat(cfg.Override); err != nil {
			return "", fmt.Errorf("keylog: --libssl override %q: %w", cfg.Override, err)
		}
		return cfg.Override, nil
	}
	exePath := filepath.Join(cfg.procRoot(), strconv.Itoa(cfg.PID), "exe")
	if _, err := os.Lstat(exePath); err != nil {
		return "", ErrLibraryNotFound
	}
	return exePath, nil
}

// GoTLSAttachSpec resolves the uprobe target for the GoTLS module against a
// resolved Go binary. Returns ErrGoTLSNotLinked when the symbol is absent.
func GoTLSAttachSpec(path string) (UprobeTarget, error) {
	targets, err := AttachSpec(path, []string{goTLSWriteKeyLogSymbol})
	if err != nil {
		if errors.Is(err, ErrSymbolNotFound) {
			return UprobeTarget{}, ErrGoTLSNotLinked
		}
		return UprobeTarget{}, err
	}
	return targets[0], nil
}

// AttachGoTLS is the GoTLS module's Attach entry point. It resolves the
// target and its uprobe symbol (both fully implemented and tested) but always
// returns ErrGoTLSExtractionUnimplemented: per AD-008, the MVP ships GoTLS as
// an interface-only follow-on, so no secrets are ever captured for a Go
// target and the keylog is never written to for it.
func AttachGoTLS(cfg DiscoveryConfig) (UprobeTarget, error) {
	path, err := ResolveGoBinary(cfg)
	if err != nil {
		return UprobeTarget{}, err
	}
	target, err := GoTLSAttachSpec(path)
	if err != nil {
		return UprobeTarget{}, err
	}
	return target, ErrGoTLSExtractionUnimplemented
}
