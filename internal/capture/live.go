package capture

import (
	"fmt"

	"github.com/gopacket/gopacket/pcapgo"
)

// Live copies packets from a network interface into a Writer until Stop. It
// is the sidecar's only capture backend: an in-process AF_PACKET reader, so
// the binary stays CGO-free and needs no libpcap or external capture tool in
// its image. The offline-decryption tests capture through it too.
type Live struct {
	iface string
	h     *pcapgo.EthernetHandle
	done  chan struct{}
}

// StartLive opens iface via an AF_PACKET raw socket (pcapgo.EthernetHandle)
// with a MaxCaptureLength read buffer and copies every packet it reads into w
// until Stop. The caller keeps ownership of w: Stop never closes it.
func StartLive(iface string, w *Writer) (*Live, error) {
	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("capture: open %q: %w", iface, err)
	}
	// The MTU-sized default read buffer truncates any GSO/TSO-inflated
	// frame (common on container veth interfaces), corrupting TLS record
	// reconstruction for offline decryption (see MaxCaptureLength).
	if err := h.SetCaptureLength(MaxCaptureLength); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("capture: set capture length on %q: %w", iface, err)
	}
	l := &Live{iface: iface, h: h, done: make(chan struct{})}
	go l.run(w)
	return l, nil
}

// run copies packets into w until a read fails, which is how Stop's close of
// the handle surfaces. A packet w fails to write is dropped, not fatal.
func (l *Live) run(w *Writer) {
	defer close(l.done)
	for {
		data, ci, err := l.h.ReadPacketData()
		if err != nil {
			return
		}
		_ = w.WritePacket(ci, data)
	}
}

// Stop closes the interface handle and waits for the copying goroutine to
// exit. Once it returns w is no longer written to, so the caller may embed the
// keylog into w and close it; doing either earlier races with a concurrent
// w.WritePacket (a data race on w's internal bufio.Writer, caught by -race).
func (l *Live) Stop() error {
	err := l.h.Close()
	<-l.done
	if err != nil {
		return fmt.Errorf("capture: close %q: %w", l.iface, err)
	}
	return nil
}
