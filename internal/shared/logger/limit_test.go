package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// limitedAt returns a Limited logger writing into buf whose clock reads *now.
func limitedAt(buf *bytes.Buffer, now *time.Time, interval time.Duration, burst int, opts ...Option) *Logger {
	l := New(buf, opts...).Limited(interval, burst)
	l.limit.now = func() time.Time { return *now }
	return l
}

// records decodes every JSON record in buf, one per line.
func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		recs = append(recs, decode(t, bytes.NewBufferString(line)))
	}
	buf.Reset()
	return recs
}

// Within a window only burst records are kept; the first one kept in a later
// window reports how many were dropped, and the one after it reports none.
func TestLimited_KeepsBurstThenReportsSuppressed(t *testing.T) {
	var buf bytes.Buffer
	now := time.Unix(1_000, 0)
	l := limitedAt(&buf, &now, time.Minute, 2)

	for range 5 {
		l.Warn("miss", slog.String("src", "10.0.0.1:40000"))
	}
	recs := records(t, &buf)
	require.Len(t, recs, 2, "only the burst is kept within a window")
	for _, rec := range recs {
		assert.NotContains(t, rec["context"], "suppressed", "nothing was dropped before these")
	}

	now = now.Add(59 * time.Second)
	l.Warn("miss")
	assert.Empty(t, records(t, &buf), "the window has not ended yet")

	now = now.Add(time.Second)
	l.Warn("miss", slog.String("src", "10.0.0.2:40000"))
	l.Warn("miss")
	recs = records(t, &buf)
	require.Len(t, recs, 2)
	ctx := recs[0]["context"].(map[string]any)
	assert.Equal(t, float64(4), ctx["suppressed"], "three dropped in the first window, one in the second")
	assert.Equal(t, "10.0.0.2:40000", ctx["src"], "the caller's attrs are kept alongside the count")
	assert.NotContains(t, recs[1], "context", "the count is reported once")
}

// A record below the level is dropped before the limiter sees it, so it
// neither uses up the burst nor counts as suppressed.
func TestLimited_BelowLevelIsNotCounted(t *testing.T) {
	var buf bytes.Buffer
	now := time.Unix(1_000, 0)
	l := limitedAt(&buf, &now, time.Minute, 1, WithLevel(slog.LevelWarn))

	for range 3 {
		l.Info("filtered")
	}
	l.Warn("kept")
	recs := records(t, &buf)
	require.Len(t, recs, 1)
	assert.Equal(t, "kept", recs[0]["message"])
	assert.NotContains(t, recs[0], "context", "filtered records are not suppressed ones")
}

// The suppressed count is appended to a copy: a caller's slice with spare
// capacity keeps its contents.
func TestLimited_DoesNotWriteIntoCallerSlice(t *testing.T) {
	var buf bytes.Buffer
	now := time.Unix(1_000, 0)
	l := limitedAt(&buf, &now, time.Minute, 1)
	l.Warn("miss")
	l.Warn("miss") // dropped

	backing := []slog.Attr{slog.String("src", "a"), slog.String("mine", "untouched")}
	attrs := backing[:1] // len 1, cap 2: an append would land in backing[1]
	now = now.Add(time.Minute)
	l.Warn("miss", attrs...)

	assert.Equal(t, slog.String("mine", "untouched"), backing[1])
}

// Concurrent callers share one budget: exactly burst records are kept.
func TestLimited_ConcurrentCallersShareTheBurst(t *testing.T) {
	var (
		buf syncBuffer
		wg  sync.WaitGroup
	)
	l := New(&buf).Limited(time.Hour, 10)
	for range 50 {
		wg.Go(func() { l.Warn("miss") })
	}
	wg.Wait()
	assert.Equal(t, 10, strings.Count(buf.String(), "\n"))
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes slog makes
// from many goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
