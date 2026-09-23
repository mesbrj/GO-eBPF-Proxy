package capture

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gopacket/gopacket/pcapgo"
)

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
	// The MTU-sized default read buffer truncates any GSO/TSO-inflated
	// frame (common on container veth interfaces), corrupting TLS record
	// reconstruction for offline decryption (see MaxCaptureLength).
	if err := h.SetCaptureLength(MaxCaptureLength); err != nil {
		_ = h.Close()
		_ = w.Close()
		return nil, fmt.Errorf("capture: set capture length on %q: %w", iface, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			data, ci, rerr := h.ReadPacketData()
			if rerr != nil {
				return
			}
			_ = w.WritePacket(ci, data)
		}
	}()
	return func() error {
		hErr := h.Close()
		// Wait for the reader goroutine to observe h.Close() and exit
		// before touching w: otherwise w.Close() below can race with a
		// concurrent w.WritePacket call in that goroutine (data race on
		// w's internal bufio.Writer, caught by -race).
		<-done
		return errors.Join(hErr, w.Close())
	}, nil
}
