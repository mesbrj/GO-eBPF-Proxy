package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFileAt(t *testing.T, path string, size int, mtime time.Time) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, make([]byte, size), 0o600))
	require.NoError(t, os.Chtimes(path, mtime, mtime))
}

// UT-03.5: a size cap evicts the oldest files first until the footprint fits.
func TestEnforce_EvictsOldestFirstWhenSizeCapExceeded(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeFileAt(t, filepath.Join(dir, "oldest.pcapng"), 100, base)
	writeFileAt(t, filepath.Join(dir, "middle.pcapng"), 100, base.Add(time.Hour))
	writeFileAt(t, filepath.Join(dir, "newest.pcapng"), 100, base.Add(2*time.Hour))

	r := Retention{Dir: dir, MaxBytes: 150, Clock: newManualClock(base.Add(3 * time.Hour))}
	require.NoError(t, r.Enforce())

	_, err := os.Stat(filepath.Join(dir, "oldest.pcapng"))
	assert.True(t, os.IsNotExist(err), "oldest file must be evicted first")
	_, err = os.Stat(filepath.Join(dir, "newest.pcapng"))
	assert.NoError(t, err, "newest file must survive")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var total int64
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		total += info.Size()
	}
	assert.LessOrEqual(t, total, int64(150), "footprint must stay within the size cap")
}

// UT-03.5: a file older than MaxAge is evicted even when the size cap isn't hit.
func TestEnforce_EvictsFilesOlderThanMaxAge(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeFileAt(t, filepath.Join(dir, "stale.pcapng"), 10, base)
	writeFileAt(t, filepath.Join(dir, "fresh.pcapng"), 10, base.Add(23*time.Hour))

	r := Retention{Dir: dir, MaxAge: 24 * time.Hour, Clock: newManualClock(base.Add(25 * time.Hour))}
	require.NoError(t, r.Enforce())

	_, err := os.Stat(filepath.Join(dir, "stale.pcapng"))
	assert.True(t, os.IsNotExist(err), "file older than MaxAge must be evicted")
	_, err = os.Stat(filepath.Join(dir, "fresh.pcapng"))
	assert.NoError(t, err, "file within MaxAge must survive")
}

// UT-03.5: with neither cap exceeded, Enforce evicts nothing.
func TestEnforce_NoopWhenWithinBounds(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeFileAt(t, filepath.Join(dir, "a.pcapng"), 10, base)

	r := Retention{Dir: dir, MaxBytes: 1000, MaxAge: time.Hour, Clock: newManualClock(base.Add(time.Minute))}
	require.NoError(t, r.Enforce())

	_, err := os.Stat(filepath.Join(dir, "a.pcapng"))
	assert.NoError(t, err, "files within both caps must not be evicted")
}

// UT-03.5: default teardown (Retain=false) wipes the artifact directory.
func TestCleanup_WipesDirByDefault(t *testing.T) {
	dir := t.TempDir()
	writeFileAt(t, filepath.Join(dir, "dump.pcapng"), 10, time.Now())
	writeFileAt(t, filepath.Join(dir, "sslkeylog.log"), 10, time.Now())

	r := Retention{Dir: dir}
	require.NoError(t, r.Cleanup())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "default teardown must wipe all artifacts")
}

// UT-03.5: --retain (Retain=true) disables the purge.
func TestCleanup_RetainPreservesArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeFileAt(t, filepath.Join(dir, "dump.pcapng"), 10, time.Now())

	r := Retention{Dir: dir, Retain: true}
	require.NoError(t, r.Cleanup())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "--retain must preserve artifacts across teardown")
}

// UT-03.6: a group/other-accessible directory is refused as a write target.
func TestCheckTarget_RefusesWorldAccessibleDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755)) // #nosec G302 -- deliberately world-accessible to test CheckTarget's refusal

	err := CheckTarget(dir)
	assert.ErrorIs(t, err, ErrWorldAccessibleTarget)
}

// UT-03.6: a secret-grade (0700) directory is an allowed write target, and a
// not-yet-created directory is allowed (the writer creates it 0700).
func TestCheckTarget_AllowsSecretGradeOrMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sidecar")
	require.NoError(t, os.Mkdir(dir, 0o700))
	assert.NoError(t, CheckTarget(dir))

	assert.NoError(t, CheckTarget(filepath.Join(dir, "not-yet-created")))
}
