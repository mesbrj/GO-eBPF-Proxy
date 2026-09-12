package capture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
	var _ Clock = (*ManualClock)(nil)

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mc := NewManualClock(start)

	readNow := func(c Clock) time.Time { return c.Now() }
	assert.True(t, readNow(mc).Equal(start))
}

// ManualClock lets tests assert exact, deterministic deltas instead of
// tolerating wall-clock jitter.
func TestManualClock_AdvanceProducesExactDelta(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mc := NewManualClock(start)

	assert.True(t, mc.Now().Equal(start))
	got := mc.Advance(5 * time.Second)
	assert.True(t, got.Equal(start.Add(5*time.Second)))
	assert.True(t, mc.Now().Equal(start.Add(5*time.Second)))
}

// A non-positive Advance must never move the clock backward: ManualClock
// preserves the monotonic-non-decreasing invariant SystemClock has for free.
func TestManualClock_NonPositiveAdvanceIgnored(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mc := NewManualClock(start)

	got := mc.Advance(-5 * time.Second)
	assert.True(t, got.Equal(start), "negative advance must be ignored")
	got = mc.Advance(0)
	assert.True(t, got.Equal(start), "zero advance must be a no-op")
}
