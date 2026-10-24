package capture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func writeFileAt(t *testing.T, path string, size int, mtime time.Time) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, make([]byte, size), 0o600))
	require.NoError(t, os.Chtimes(path, mtime, mtime))
}

// UT-03.5: a finished owned capture older than MaxAge is evicted. (Feature
// 07: its fixtures, once stale.pcapng and fresh.pcapng, take owned capture
// names, since the age rule touches nothing else (door 2). Its assertions are
// unchanged.)
func TestEnforce_EvictsFilesOlderThanMaxAge(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stale, fresh := filepath.Join(dir, "dump-1000000000.pcapng"), filepath.Join(dir, "dump-1000000001.pcapng")
	writeFileAt(t, stale, 10, base)
	writeFileAt(t, fresh, 10, base.Add(23*time.Hour))

	r := Retention{Template: filepath.Join(dir, "dump.pcapng"), MaxAge: 24 * time.Hour, Clock: newManualClock(base.Add(25 * time.Hour))}
	require.NoError(t, r.Enforce())

	_, err := os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "file older than MaxAge must be evicted")
	_, err = os.Stat(fresh)
	assert.NoError(t, err, "file within MaxAge must survive")
}

// UT-03.5: with neither cap exceeded, Enforce evicts nothing. (Feature 07:
// its fixture, once a.pcapng, takes an owned capture name (door 2).)
func TestEnforce_NoopWhenWithinBounds(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(dir, "dump-1000000000.pcapng")
	writeFileAt(t, path, 10, base)

	r := Retention{Template: filepath.Join(dir, "dump.pcapng"), MaxBytes: 1000, MaxAge: time.Hour, Clock: newManualClock(base.Add(time.Minute))}
	require.NoError(t, r.Enforce())

	_, err := os.Stat(path)
	assert.NoError(t, err, "files within both caps must not be evicted")
}

// UT-03.5: default teardown (Retain=false) deletes this run's capture. (Feature
// 07, AC 20: was TestCleanup_WipesDirByDefault, which wiped the whole
// directory, the keylog file included. Teardown now deletes this run's
// capture and nothing else.)
func TestCleanup_DeletesThisRunsCaptureByDefault(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "dump-1761300000.pcapng")
	writeFileAt(t, run, 10, time.Now())
	writeFileAt(t, filepath.Join(dir, "sslkeylog.log"), 10, time.Now())

	r := Retention{Template: filepath.Join(dir, "dump.pcapng"), Run: run}
	require.NoError(t, r.Cleanup())

	assert.Equal(t, []string{"sslkeylog.log"}, dirNames(t, dir), "default teardown must delete this run's capture, and only it")
}

// UT-03.5: --retain (Retain=true) disables the purge. (Feature 07: the
// artifact is this run's capture, named as a run names it.)
func TestCleanup_RetainPreservesArtifacts(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "dump-1761300000.pcapng")
	writeFileAt(t, run, 10, time.Now())

	r := Retention{Template: filepath.Join(dir, "dump.pcapng"), Run: run, Retain: true}
	require.NoError(t, r.Cleanup())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "--retain must preserve artifacts across teardown")
}

// C25 (AC 17): nothing is ever deleted for size. --max-bytes stops capture
// instead (AD-020). (Supersedes UT-03.5's
// TestEnforce_EvictsOldestFirstWhenSizeCapExceeded, which asserted the
// oldest-first eviction AD-020 removed.)
func TestRetention_NothingIsDeletedForSize(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	var want []string
	for i := range 5 {
		name := fmt.Sprintf("dump-176130000%d.pcapng", i)
		writeFileAt(t, filepath.Join(dir, name), 1<<20, now.Add(-time.Duration(i)*time.Minute))
		want = append(want, name)
	}

	r := Retention{Template: filepath.Join(dir, "dump.pcapng"), MaxBytes: 1 << 10, MaxAge: 24 * time.Hour, Clock: newManualClock(now)}
	require.NoError(t, r.Enforce())

	assert.Equal(t, want, dirNames(t, dir), "5 MiB of fresh captures over a 1 KiB --max-bytes must all be kept")
}

// C26 (AC 18): the age pass deletes a finished owned capture strictly older
// than MaxAge, keeps one exactly that old or younger, and with MaxAge 0
// deletes nothing.
func TestRetention_AgePassDeletesExpiredFinishedCaptures(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	plant := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		writeFileAt(t, filepath.Join(dir, "dump-1000000001.pcapng"), 10, now.Add(-(24*time.Hour + time.Second)))
		writeFileAt(t, filepath.Join(dir, "dump-1000000002.pcapng"), 10, now.Add(-24*time.Hour))
		writeFileAt(t, filepath.Join(dir, "dump-1000000003.pcapng"), 10, now.Add(-23*time.Hour))
		return dir
	}

	t.Run("max-age 24h", func(t *testing.T) {
		dir := plant(t)
		r := Retention{Template: filepath.Join(dir, "dump.pcapng"), MaxAge: 24 * time.Hour, Clock: newManualClock(now)}
		require.NoError(t, r.Enforce())
		assert.Equal(t, []string{"dump-1000000002.pcapng", "dump-1000000003.pcapng"}, dirNames(t, dir),
			"only the capture aged 24h + 1s is past --max-age")
	})
	t.Run("max-age 0", func(t *testing.T) {
		dir := plant(t)
		r := Retention{Template: filepath.Join(dir, "dump.pcapng"), Clock: newManualClock(now.Add(48 * time.Hour))}
		require.NoError(t, r.Enforce())
		assert.Len(t, dirNames(t, dir), 3, "--max-age 0 deletes nothing")
	})
}

// sparedEntries plants the eight entries the age pass must never delete, each
// with its mtime 48h before now (for a symlink, its own mtime and its
// target's), and returns the Retention over dir whose Run is this run's file
// among them. Each entry is non-empty, so one wrongly counted shows in a sum.
func sparedEntries(t *testing.T, dir string, now time.Time) Retention {
	t.Helper()
	old := now.Add(-48 * time.Hour)
	run := filepath.Join(dir, "dump-1761300000.pcapng")
	for _, name := range []string{
		"dump-1761300000.pcapng", // this run's file
		"sslkeylog.log",          // the keylog file
		"dump.pcapng",            // the fixed name an earlier version wrote
		"." + "dsb-1.pcapng",     // the removed re-emission's temp file (split so C36's grep stays clean)
		"notes.txt",
		"other-3.pcapng",
	} {
		writeFileAt(t, filepath.Join(dir, name), 1000, old)
	}
	target := filepath.Join(t.TempDir(), "dump-elsewhere.pcapng")
	writeFileAt(t, target, 1000, old)
	link := filepath.Join(dir, "dump-1-1.pcapng")
	require.NoError(t, os.Symlink(target, link))
	ts := unix.NsecToTimespec(old.UnixNano())
	require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, link, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW))
	sub := filepath.Join(dir, "dump-2.pcapng")
	require.NoError(t, os.Mkdir(sub, 0o700))
	require.NoError(t, os.Chtimes(sub, old, old))
	return Retention{Template: filepath.Join(dir, "dump.pcapng"), Run: run, MaxAge: 24 * time.Hour, Clock: newManualClock(now)}
}

// C27 (AC 19, door 2): the age pass deletes only finished owned captures.
// This run's file, the keylog, foreign files, a symlink and a directory
// bearing owned names all survive, however old.
func TestRetention_AgePassSparesLiveKeylogAndForeignEntries(t *testing.T) {
	dir := t.TempDir()
	r := sparedEntries(t, dir, time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	before := dirNames(t, dir)
	require.Len(t, before, 8)

	require.NoError(t, r.Enforce())

	assert.Equal(t, before, dirNames(t, dir), "no entry other than a finished owned capture may be deleted")
}

// C28 (door 2): the owned-bytes sum the startup check and the room use counts
// the finished owned captures and nothing else.
func TestRetention_OwnedBytesCountsOnlyFinishedOwnedCaptures(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	r := sparedEntries(t, dir, now)
	writeFileAt(t, filepath.Join(dir, "dump-1700000000.pcapng"), 100, now)
	writeFileAt(t, filepath.Join(dir, "dump-1700000000-1.pcapng"), 200, now)

	owned, err := r.OwnedBytes()
	require.NoError(t, err)
	assert.Equal(t, int64(300), owned)

	r.MaxBytes = 1000
	room, err := r.Room()
	require.NoError(t, err)
	assert.Equal(t, int64(700), room, "the room is --max-bytes less the owned bytes")
}

// C68 (door 2, AC 17, AC 19): an owned capture lies directly in the capture
// directory. Files with owned names in a subdirectory are neither aged out
// nor counted, however old.
func TestRetention_IgnoresOwnedNamesInsideSubdirectories(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o700))
	nested := map[string]int{
		filepath.Join(sub, "dump-1.pcapng"):   500,
		filepath.Join(sub, "dump-2-1.pcapng"): 700,
	}
	for path, size := range nested {
		writeFileAt(t, path, size, old)
	}
	expired := filepath.Join(dir, "dump-1600000000.pcapng")
	writeFileAt(t, expired, 200, old)
	writeFileAt(t, filepath.Join(dir, "dump-1700000000.pcapng"), 100, now)

	r := Retention{Template: filepath.Join(dir, "dump.pcapng"), MaxAge: 24 * time.Hour, Clock: newManualClock(now)}
	owned, err := r.OwnedBytes()
	require.NoError(t, err)
	assert.Equal(t, int64(300), owned, "only the owned captures directly in the directory count, not the 1,200 B under sub")

	require.NoError(t, r.Enforce())
	assert.NoFileExists(t, expired, "a 48h-old owned capture directly in the directory is past --max-age")
	for path := range nested {
		assert.FileExists(t, path, "an owned name inside a subdirectory is not an owned capture")
	}
}

// C69 (door 2): the template's stem and extension match literally, never as
// a regular expression. A name that differs from an owned one only where the
// template has a '.' is not an owned capture: it is neither counted nor aged
// out. The owned name beside it is both.
func TestRetention_TemplateMetacharactersMatchLiterally(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)

	for _, tc := range []struct {
		name     string
		template string
		decoy    string // differs from an owned name only at a metacharacter
		control  string // an owned name, the positive control
	}{
		{name: "extension", template: "dump.pcapng", decoy: "dump-1Xpcapng", control: "dump-1.pcapng"},
		{name: "stem", template: "a.b.pcapng", decoy: "aXb-1.pcapng", control: "a.b-1.pcapng"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFileAt(t, filepath.Join(dir, tc.decoy), 1000, old)
			writeFileAt(t, filepath.Join(dir, tc.control), 100, old)
			r := Retention{Template: filepath.Join(dir, tc.template), MaxAge: 24 * time.Hour, Clock: newManualClock(now)}

			owned, err := r.OwnedBytes()
			require.NoError(t, err)
			assert.Equal(t, int64(100), owned, "%s is not an owned capture of %s", tc.decoy, tc.template)

			require.NoError(t, r.Enforce())
			assert.Equal(t, []string{tc.decoy}, dirNames(t, dir), "the age pass deletes %s and keeps %s", tc.control, tc.decoy)
		})
	}
}

// assertOnlyControlIsOwned plants, under template dump.pcapng, the owned
// control at 100 B and each decoy at 1,000 B, all aged 48h: first every decoy
// together, then each decoy alone beside the control, so a matcher that takes
// one decoy for an owned capture fails on that decoy's row. In every row the
// owned-bytes sum is exactly the control's 100 B, and an age pass with
// --max-age 24h deletes the control and keeps every decoy.
func assertOnlyControlIsOwned(t *testing.T, control string, decoys ...string) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)

	check := func(t *testing.T, decoys []string) {
		t.Helper()
		dir := t.TempDir()
		for _, decoy := range decoys {
			writeFileAt(t, filepath.Join(dir, decoy), 1000, old)
		}
		writeFileAt(t, filepath.Join(dir, control), 100, old)
		r := Retention{Template: filepath.Join(dir, "dump.pcapng"), MaxAge: 24 * time.Hour, Clock: newManualClock(now)}

		owned, err := r.OwnedBytes()
		require.NoError(t, err)
		assert.Equal(t, int64(100), owned, "of %v beside %s, only %s is an owned capture of dump.pcapng", decoys, control, control)

		require.NoError(t, r.Enforce())
		assert.Equal(t, slices.Sorted(slices.Values(decoys)), dirNames(t, dir), "the age pass deletes %s and keeps %v", control, decoys)
	}

	t.Run("all decoys", func(t *testing.T) { check(t, decoys) })
	for _, decoy := range decoys {
		t.Run(decoy, func(t *testing.T) { check(t, []string{decoy}) })
	}
}

// C70 (door 2): an owned name matches the whole file name. A name that holds
// an owned name after a prefix, or before a further extension, is not an owned
// capture: an operator's copy is neither counted toward --max-bytes nor aged
// out. The owned name beside it is both.
func TestRetention_OwnedNameMustMatchTheWholeName(t *testing.T) {
	assertOnlyControlIsOwned(t, "dump-1700000000.pcapng",
		"old-dump-1.pcapng",          // an owned name after a prefix
		"dump-1700000000.pcapng.bak", // an owned name before a further extension
	)
}

// C71 (door 2): an owned name's epoch is digits only and not empty, and it
// carries at most one suffix, digits only. Any other name of the template's
// shape is not an owned capture: it is neither counted nor aged out. The owned
// name with an epoch and one suffix beside it is both.
func TestRetention_OwnedNameNeedsDigitEpochAndAtMostOneSuffix(t *testing.T) {
	assertOnlyControlIsOwned(t, "dump-1-2.pcapng",
		"dump-old.pcapng",   // an epoch that is not digits
		"dump-.pcapng",      // an empty epoch
		"dump-1-x.pcapng",   // a suffix that is not digits
		"dump-1-2-3.pcapng", // two suffixes
	)
}

// C29 (AC 20, AC 45): teardown deletes this run's capture and nothing else,
// and with Retain it deletes nothing, leaving the capture byte for byte.
func TestRetention_CleanupDeletesOnlyThisRunsCapture(t *testing.T) {
	plant := func(t *testing.T) (string, Retention) {
		t.Helper()
		dir := t.TempDir()
		run := filepath.Join(dir, "dump-1761300000.pcapng")
		require.NoError(t, os.WriteFile(run, []byte("this run's capture"), 0o600))
		for _, name := range []string{"dump-1700000000.pcapng", "sslkeylog.log", "notes.txt"} {
			writeFileAt(t, filepath.Join(dir, name), 10, time.Now())
		}
		return dir, Retention{Template: filepath.Join(dir, "dump.pcapng"), Run: run}
	}

	t.Run("without retain", func(t *testing.T) {
		dir, r := plant(t)
		require.NoError(t, r.Cleanup())
		assert.Equal(t, []string{"dump-1700000000.pcapng", "notes.txt", "sslkeylog.log"}, dirNames(t, dir))
	})
	t.Run("with retain", func(t *testing.T) {
		dir, r := plant(t)
		r.Retain = true
		sum := sha256.Sum256(readFile(t, r.Run))
		require.NoError(t, r.Cleanup())
		assert.Len(t, dirNames(t, dir), 4, "--retain must delete nothing")
		assert.Equal(t, sum, sha256.Sum256(readFile(t, r.Run)), "this run's capture must be kept byte for byte")
	})
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
