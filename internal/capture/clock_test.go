package capture

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// manualClock is a deterministic, injectable Clock for tests: it starts at a
// fixed instant and only advances when told to, so timestamp-alignment tests
// can assert exact deltas instead of racing the wall clock.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

// newManualClock returns a manualClock starting at start.
func newManualClock(start time.Time) *manualClock {
	return &manualClock{now: start}
}

// Now returns the current simulated time.
func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the simulated clock forward by d and returns the new time. A
// non-positive d is ignored so Now never moves backward.
func (c *manualClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > 0 {
		c.now = c.now.Add(d)
	}
	return c.now
}

// UT-03.2: consecutive SystemClock reads never go backward (the practical,
// externally observable form of "monotonic" for a wall-clock source).
func TestSystemClock_MonotonicNonDecreasing(t *testing.T) {
	var c SystemClock
	prev := c.Now()
	for i := 0; i < 1000; i++ {
		cur := c.Now()
		assert.False(t, cur.Before(prev), "clock must never go backward")
		prev = cur
	}
}

// UT-03.2: the same Clock abstraction is injectable wherever a timestamp
// source is needed, letting capture and any paired component share one
// instance instead of racing independent wall clocks.
func TestClock_InjectableAcrossConsumers(t *testing.T) {
	var _ Clock = SystemClock{}
	var _ Clock = (*manualClock)(nil)

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mc := newManualClock(start)

	readNow := func(c Clock) time.Time { return c.Now() }
	assert.True(t, readNow(mc).Equal(start))
}

// manualClock lets tests assert exact, deterministic deltas instead of
// tolerating wall-clock jitter.
func TestManualClock_AdvanceProducesExactDelta(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mc := newManualClock(start)

	assert.True(t, mc.Now().Equal(start))
	got := mc.Advance(5 * time.Second)
	assert.True(t, got.Equal(start.Add(5*time.Second)))
	assert.True(t, mc.Now().Equal(start.Add(5*time.Second)))
}

// A non-positive Advance must never move the clock backward: manualClock
// preserves the monotonic-non-decreasing invariant SystemClock has for free.
func TestManualClock_NonPositiveAdvanceIgnored(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mc := newManualClock(start)

	got := mc.Advance(-5 * time.Second)
	assert.True(t, got.Equal(start), "negative advance must be ignored")
	got = mc.Advance(0)
	assert.True(t, got.Equal(start), "zero advance must be a no-op")
}
