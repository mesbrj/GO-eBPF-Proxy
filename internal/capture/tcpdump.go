// Package capture: tcpdump fallback/parity backend, plus the in-process
// gopacket live-capture path Start falls back to when tcpdump is absent.
package capture

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gopacket/gopacket/pcapgo"
)

// lookPath resolves the tcpdump binary; overridable in tests so backend
// selection doesn't depend on whether tcpdump happens to be installed.
var lookPath = exec.LookPath

// backendFor reports which backend Start would choose for the given tcpdump
// lookup function: "tcpdump" when found, "gopacket" otherwise. Exposed
// separately so the fallback-selection edge case is unit-testable without a
// real capture (spec edge case: tcpdump unavailable -> gopacket fallback).
func backendFor(lp func(string) (string, error)) string {
	if _, err := lp("tcpdump"); err == nil {
		return "tcpdump"
	}
	return "gopacket"
}

// Start captures iface to path, preferring tcpdump when it is on PATH and
// falling back to the in-process gopacket backend otherwise. It returns a
// stop func that cleanly terminates the capture.
func Start(iface, path string) (stop func() error, err error) {
	if backendFor(lookPath) == "tcpdump" {
		return startTcpdump(iface, path)
	}
	return startGopacket(iface, path)
}

// startTcpdump runs `tcpdump -i <iface> -w <path>` as a subprocess and
// returns a stop func that signals it to exit and waits for a clean pcap
// trailer to be flushed.
func startTcpdump(iface, path string) (stop func() error, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("capture: create capture dir: %w", err)
	}
	cmd := exec.Command("tcpdump", "-i", iface, "-w", path, "-U") // #nosec G204 -- iface/path are operator-supplied config, not raw user input
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("capture: start tcpdump: %w", err)
	}
	return func() error {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return fmt.Errorf("capture: stop tcpdump: %w", err)
		}
		return cmd.Wait()
	}, nil
}

// startGopacket reads live packets off iface via an AF_PACKET raw socket and
// writes each one into a pcapng Writer at path -- the in-process alternative
// to the tcpdump backend.
func startGopacket(iface, path string) (stop func() error, err error) {
	w, err := NewWriter(path, Options{})
	if err != nil {
		return nil, err
	}
	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("capture: open %q: %w", iface, err)
	}
	go func() {
		for {
			data, ci, rerr := h.ReadPacketData()
			if rerr != nil {
				return
			}
			_ = w.WritePacket(ci, data)
		}
	}()
	return func() error {
		return errors.Join(h.Close(), w.Close())
	}, nil
}
