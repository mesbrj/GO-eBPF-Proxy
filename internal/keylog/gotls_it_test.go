//go:build integration

package keylog

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildGoProbe compiles a tiny Go program (source in main.go's content) into
// dir/probe and returns its path. Skips if the go toolchain can't build it
// (e.g. no network for an isolated GOPROXY, though this uses stdlib only).
func buildGoProbe(t *testing.T, dir, source string) string {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module probe\n\ngo 1.25\n"), 0o600))

	out := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", out, ".") // #nosec G204 -- fixed args, test-controlled dir
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build go probe binary: %v: %s", err, output)
	}
	return out
}

const tlsHandshakeSource = `package main

import (
	"crypto/tls"
	"net"
)

func main() {
	c1, c2 := net.Pipe()
	go func() {
		srv := tls.Server(c2, &tls.Config{})
		_ = srv.Handshake()
	}()
	cli := tls.Client(c1, &tls.Config{InsecureSkipVerify: true})
	_ = cli.Handshake()
}
`

const noTLSSource = `package main

func main() {
	println("no tls here")
}
`

// IT-02.5 (gated): the GoTLS module resolves the writeKeyLog uprobe target on
// a Go binary that actually performs a TLS handshake.
func TestGoTLSAttachSpec_ResolvesOnHandshakeBinary(t *testing.T) {
	dir := t.TempDir()
	bin := buildGoProbe(t, dir, tlsHandshakeSource)

	target, err := GoTLSAttachSpec(bin)
	require.NoError(t, err)
	assert.Equal(t, bin, target.Library)
	assert.Equal(t, "crypto/tls.(*Config).writeKeyLog", target.Symbol)
}

// IT-02.5 (gated): a binary that never links crypto/tls has no symbol to
// attach to -> typed ErrGoTLSNotLinked, not a silent no-op.
func TestGoTLSAttachSpec_NotLinkedTypedError(t *testing.T) {
	dir := t.TempDir()
	bin := buildGoProbe(t, dir, noTLSSource)

	_, err := GoTLSAttachSpec(bin)
	assert.ErrorIs(t, err, ErrGoTLSNotLinked)
}

// IT-02.5 (gated): AttachGoTLS resolves the target but never captures secrets
// in the MVP (AD-008: GoTLS is interface-only) -- it always reports
// ErrGoTLSExtractionUnimplemented, so the keylog is never written to for a Go
// target until a follow-on implements the Go-ABI-aware uprobe.
func TestAttachGoTLS_GatedUnimplemented(t *testing.T) {
	dir := t.TempDir()
	bin := buildGoProbe(t, dir, tlsHandshakeSource)

	_, err := AttachGoTLS(DiscoveryConfig{Override: bin})
	assert.ErrorIs(t, err, ErrGoTLSExtractionUnimplemented)
}
