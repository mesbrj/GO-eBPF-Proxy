//go:build integration

package proxy

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfpkg "github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
)

// startEcho starts a loopback TCP echo server and returns its address.
func startEcho(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

func serveRelay(t *testing.T, r *Resolver) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	relay := NewRelay(r, WithDialTimeout(2*time.Second))
	go func() { _ = relay.Serve(ln) }()
	return ln.Addr().(*net.TCPAddr)
}

// IT-01.9: the relay resolves the original destination and raw-pipes bytes intact.
func TestRelay_ResolvesAndPipesIntact(t *testing.T) {
	up := startEcho(t)
	od, err := ebpfpkg.OrigDst(netip.MustParseAddr("127.0.0.1"), uint16(up.Port))
	require.NoError(t, err)

	r := NewResolver(&stubLookuper{script: []error{nil}, val: od}, WithRetry(0, 0))
	relayAddr := serveRelay(t, r)

	c, err := net.Dial("tcp", relayAddr.String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	msg := []byte("hello-through-the-relay")
	_, err = c.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, len(msg))
	require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf, "bytes must be piped through unchanged")
}

// IT-01.10: an unresolved connection is closed (RST), never forwarded; miss recorded.
func TestRelay_FailsClosedOnMiss(t *testing.T) {
	r := NewResolver(&stubLookuper{}, WithRetry(0, 0)) // always misses
	relayAddr := serveRelay(t, r)

	c, err := net.Dial("tcp", relayAddr.String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	// Write a payload: on a fail-open forward it would reach a default upstream
	// and (for an echo) come back; the fail-closed relay must never echo it.
	payload := []byte("must-not-be-forwarded")
	_, _ = c.Write(payload)

	require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, len(payload))
	n, rerr := c.Read(buf)
	assert.Equal(t, 0, n, "no bytes may be forwarded/echoed on a miss")
	require.Error(t, rerr, "relay must close the connection")

	// Discriminate fail-closed from fail-open: a relay that kept the connection
	// open (piping to a default) would time out here, not error with a reset.
	var ne net.Error
	if errors.As(rerr, &ne) {
		assert.False(t, ne.Timeout(), "connection must be actively reset, not left open")
	}
	// The relay resets via SetLinger(0)+Close, so the peer observes ECONNRESET.
	assert.ErrorIs(t, rerr, syscall.ECONNRESET, "fail-closed must RST (got %v)", rerr)

	assert.Eventually(t, func() bool { return r.Misses() == 1 }, time.Second, 10*time.Millisecond,
		"a definitive miss must be recorded")
}
