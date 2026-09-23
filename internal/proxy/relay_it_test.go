//go:build integration

package proxy

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
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

// CAPTURE-11 (feature-03 AC): a successful resolve invokes onResolved with the
// original destination, before dialing -- the hook operators use to log it.
func TestRelay_LogsResolvedOriginalDestination(t *testing.T) {
	up := startEcho(t)
	od, err := ebpfpkg.OrigDst(netip.MustParseAddr("127.0.0.1"), uint16(up.Port)) // #nosec G115 -- TCPAddr.Port is always 0-65535
	require.NoError(t, err)
	want := ebpfpkg.AddrPort(od)

	r := NewResolver(&stubLookuper{script: []error{nil}, val: od}, WithRetry(0, 0))

	var got netip.AddrPort
	var mu sync.Mutex
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	relay := NewRelay(r, WithDialTimeout(2*time.Second), WithOnResolved(func(dst netip.AddrPort) {
		mu.Lock()
		got = dst
		mu.Unlock()
	}))
	go func() { _ = relay.Serve(ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got == want
	}, 2*time.Second, 10*time.Millisecond, "onResolved must be called with the exact resolved original destination")
}

// IT-01.9: the relay resolves the original destination and raw-pipes bytes intact.
func TestRelay_ResolvesAndPipesIntact(t *testing.T) {
	up := startEcho(t)
	od, err := ebpfpkg.OrigDst(netip.MustParseAddr("127.0.0.1"), uint16(up.Port)) // #nosec G115 -- TCPAddr.Port is always 0-65535
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

	// The relay resets via SetLinger(0)+Close the moment the lookup misses, so
	// on loopback the RST can beat Dial's return and surface there (connect's
	// pending-error check) instead of on the Read. The client deliberately
	// sends nothing: a Write could consume the reset (Linux reports it once,
	// leaving the Read an EOF), and data the relay never read would make even
	// a graceful Close send an RST, hiding a relay that stopped resetting.
	resetErr := func() error {
		c, err := net.Dial("tcp", relayAddr.String())
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()

		require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, err := c.Read(make([]byte, 64))
		assert.Equal(t, 0, n, "no bytes may reach the client on a miss")
		return err
	}()
	require.Error(t, resetErr, "relay must close the connection")

	// Discriminate fail-closed from fail-open: a relay that kept the connection
	// open (piping to a default) would time out here, not error with a reset.
	var ne net.Error
	if errors.As(resetErr, &ne) {
		assert.False(t, ne.Timeout(), "connection must be actively reset, not left open")
	}
	// A graceful close would surface as EOF instead: only a reset passes.
	assert.ErrorIs(t, resetErr, syscall.ECONNRESET, "fail-closed must RST (got %v)", resetErr)

	assert.Eventually(t, func() bool { return r.Misses() == 1 }, time.Second, 10*time.Millisecond,
		"a definitive miss must be recorded")
}
