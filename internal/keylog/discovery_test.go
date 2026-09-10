package keylog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realLibssl is a system libssl present on the dev/CI image; skip ELF-backed
// tests when it is unavailable rather than failing the suite.
func realLibssl(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.3",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("no system libssl.so found for ELF-backed test")
	return ""
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// UT-02.7: --libssl override is honoured verbatim.
func TestResolveLibssl_OverrideHonoured(t *testing.T) {
	dir := t.TempDir()
	libPath := filepath.Join(dir, "custom-libssl.so")
	writeFile(t, libPath, "fake")

	got, err := ResolveLibssl(DiscoveryConfig{Override: libPath})
	require.NoError(t, err)
	assert.Equal(t, libPath, got)
}

// UT-02.7: override pointing at a non-existent path is a typed/wrapped error.
func TestResolveLibssl_OverrideMissing(t *testing.T) {
	_, err := ResolveLibssl(DiscoveryConfig{Override: "/does/not/exist.so"})
	assert.Error(t, err)
}

// UT-02.7: resolves the library from /proc/<pid>/maps.
func TestResolveLibssl_FromMaps(t *testing.T) {
	procRoot := t.TempDir()
	mapsPath := filepath.Join(procRoot, "4242", "maps")
	writeFile(t, mapsPath, ""+
		"7f0000000000-7f0000020000 r--p 00000000 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6\n"+
		"7f0000021000-7f0000090000 r-xp 00021000 08:01 2 /usr/lib/x86_64-linux-gnu/libssl.so.3\n")

	got, err := ResolveLibssl(DiscoveryConfig{PID: 4242, ProcRoot: procRoot})
	require.NoError(t, err)
	assert.Equal(t, "/usr/lib/x86_64-linux-gnu/libssl.so.3", got)
}

// UT-02.7: when maps has no libssl entry, falls back to ld.so.cache (ldconfig -p).
func TestResolveLibssl_FromLdConfigFallback(t *testing.T) {
	procRoot := t.TempDir()
	mapsPath := filepath.Join(procRoot, "77", "maps")
	writeFile(t, mapsPath, "7f0000000000-7f0000020000 r--p 00000000 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6\n")

	cfg := DiscoveryConfig{
		PID:      77,
		ProcRoot: procRoot,
		ListDynamicLibraries: func() ([]byte, error) {
			return []byte("libssl.so.3 (libc6,x86-64) => /opt/custom/libssl.so.3\n"), nil
		},
	}
	got, err := ResolveLibssl(cfg)
	require.NoError(t, err)
	assert.Equal(t, "/opt/custom/libssl.so.3", got)
}

// UT-02.7: statically linked binary (no maps/ldconfig hit) resolves to the executable.
func TestResolveLibssl_StaticBinaryFallsBackToExecutable(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "99")
	require.NoError(t, os.MkdirAll(pidDir, 0o750))
	writeFile(t, filepath.Join(pidDir, "maps"), "7f0000000000-7f0000020000 r--p 00000000 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6\n")
	// Symlink exe -> some real file so os.Lstat succeeds.
	target := filepath.Join(procRoot, "target-bin")
	writeFile(t, target, "bin")
	require.NoError(t, os.Symlink(target, filepath.Join(pidDir, "exe")))

	cfg := DiscoveryConfig{
		PID:      99,
		ProcRoot: procRoot,
		ListDynamicLibraries: func() ([]byte, error) {
			return []byte("libc.so.6 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libc.so.6\n"), nil
		},
	}
	got, err := ResolveLibssl(cfg)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(pidDir, "exe"), got)
}

// UT-02.7: no maps, no ldconfig hit, no executable -> typed not-found error.
func TestResolveLibssl_NotFound(t *testing.T) {
	procRoot := t.TempDir()
	cfg := DiscoveryConfig{
		PID:      1,
		ProcRoot: procRoot,
		ListDynamicLibraries: func() ([]byte, error) {
			return []byte(""), nil
		},
	}
	_, err := ResolveLibssl(cfg)
	assert.ErrorIs(t, err, ErrLibraryNotFound)
}

// UT-02.9: AttachSpec builds targets for symbols present in a real libssl.
func TestAttachSpec_ResolvesPresentSymbol(t *testing.T) {
	lib := realLibssl(t)
	targets, err := AttachSpec(lib, []string{"SSL_write"})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, lib, targets[0].Library)
	assert.Equal(t, "SSL_write", targets[0].Symbol)
}

// UT-02.9: a missing symbol yields a typed error, not a silent no-op.
func TestAttachSpec_MissingSymbolTypedError(t *testing.T) {
	lib := realLibssl(t)
	_, err := AttachSpec(lib, []string{"SSL_definitely_not_a_real_symbol"})
	assert.ErrorIs(t, err, ErrSymbolNotFound)
}
