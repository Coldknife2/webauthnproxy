package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateSpec is "N requests per window"; the zero value means no limit.
type RateSpec struct {
	Count  int
	Window time.Duration
}

func (r RateSpec) Enabled() bool { return r.Count > 0 && r.Window > 0 }

// ParseRate parses "20/1m", "100/1h" or "20" (per minute). "0" and "off" disable the limit.
func ParseRate(s string) (RateSpec, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "off" {
		return RateSpec{}, nil
	}
	count, win, found := strings.Cut(s, "/")
	n, err := strconv.Atoi(count)
	if err != nil || n < 0 {
		return RateSpec{}, fmt.Errorf("invalid rate %q (expected N/duration, e.g. 20/1m)", s)
	}
	if !found {
		return RateSpec{Count: n, Window: time.Minute}, nil
	}
	d, err := time.ParseDuration(win)
	if err != nil || d <= 0 {
		return RateSpec{}, fmt.Errorf("invalid rate %q (expected N/duration, e.g. 20/1m)", s)
	}
	return RateSpec{Count: n, Window: d}, nil
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a token bucket per key: it allows Count requests in a burst and refills Count per Window.
type Limiter struct {
	mu      sync.Mutex
	spec    RateSpec
	now     func() time.Time
	buckets map[string]*bucket
}

const maxBuckets = 20000

func NewLimiter(spec RateSpec) *Limiter {
	return &Limiter{spec: spec, now: time.Now, buckets: map[string]*bucket{}}
}

// Allow consumes one token for key. When it refuses, it also returns how long to wait.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if l == nil || !l.spec.Enabled() {
		return true, 0
	}
	now := l.now()
	burst := float64(l.spec.Count)
	rate := burst / l.spec.Window.Seconds() // tokens per second

	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			l.prune(now, burst, rate)
		}
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

// prune forgets buckets that have fully refilled: a new bucket starts full, so nothing is lost.
// If every bucket is busy (an attack with many addresses), the table is reset rather than growing without bound.
func (l *Limiter) prune(now time.Time, burst, rate float64) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*rate >= burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) >= maxBuckets {
		l.buckets = map[string]*bucket{}
	}
}

// rateKey groups IPv6 clients by /64 (one subscriber usually owns a whole /64) so a client cannot dodge the limit by changing address.
func rateKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return "unknown"
	}
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}
