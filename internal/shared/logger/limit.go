package logger

import (
	"sync"
	"time"
)

// Limited returns a Logger that writes through l but keeps at most burst
// records per interval, dropping the rest. The first record kept after a
// drop carries context.suppressed: the number dropped since the last one
// kept. Use it, one per call site, for an event something outside the
// sidecar can trigger at will, and count that event elsewhere: a dropped
// record is gone, and drops at the end of a burst are reported only once
// another record is kept.
func (l *Logger) Limited(interval time.Duration, burst int) *Logger {
	return &Logger{inner: l.inner, limit: &limiter{interval: interval, burst: burst, now: time.Now}}
}

// limiter admits at most burst records per fixed window of interval.
type limiter struct {
	interval time.Duration
	burst    int
	now      func() time.Time

	mu      sync.Mutex
	start   time.Time // start of the current window
	kept    int       // records kept in the current window
	dropped int64     // records dropped since the last one kept
}

// admit reports whether to keep a record now and, if so, how many records
// were dropped since the last one kept.
func (lim *limiter) admit() (keep bool, dropped int64) {
	now := lim.now()
	lim.mu.Lock()
	defer lim.mu.Unlock()
	if now.Sub(lim.start) >= lim.interval {
		lim.start, lim.kept = now, 0
	}
	if lim.kept >= lim.burst {
		lim.dropped++
		return false, 0
	}
	lim.kept++
	dropped, lim.dropped = lim.dropped, 0
	return true, dropped
}
