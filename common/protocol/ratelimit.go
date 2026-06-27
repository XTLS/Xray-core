package protocol

import (
	"strings"
	"sync"
	"time"
)

// RateLimiter is a shared token bucket for per-user byte/sec limits.
type RateLimiter struct {
	mu        sync.Mutex
	rate      float64
	capacity  float64
	available float64
	last      time.Time
}

var globalLimiterRegistry = newLimiterRegistry()

type limiterRegistry struct {
	mu     sync.Mutex
	byUser map[string]*RateLimiter
}

func newLimiterRegistry() *limiterRegistry {
	return &limiterRegistry{
		byUser: make(map[string]*RateLimiter),
	}
}

func normalizeLimiterKey(email, direction string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return ""
	}
	return direction + ":" + email
}

func (r *limiterRegistry) Get(email, direction string, rate uint64) *RateLimiter {
	key := normalizeLimiterKey(email, direction)
	if key == "" {
		return NewRateLimiter(rate)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	limiter, found := r.byUser[key]
	if !found {
		limiter = NewRateLimiter(rate)
		if limiter == nil {
			limiter = &RateLimiter{}
		}
		r.byUser[key] = limiter
	}
	limiter.SetRate(rate)
	return limiter
}

func NewRateLimiter(rate uint64) *RateLimiter {
	limiter := &RateLimiter{}
	limiter.SetRate(rate)
	return limiter
}

func (l *RateLimiter) SetRate(rate uint64) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if !l.last.IsZero() && l.rate > 0 {
		elapsed := now.Sub(l.last).Seconds()
		if elapsed > 0 {
			l.available += elapsed * l.rate
		}
	}

	l.rate = float64(rate)
	if rate == 0 {
		l.capacity = 0
		l.available = 0
		l.last = now
		return
	}

	capacity := float64(rate)
	if capacity < 64*1024 {
		capacity = 64 * 1024
	}
	l.capacity = capacity
	if l.available > capacity || l.last.IsZero() {
		l.available = capacity
	}
	l.last = now
}

func (l *RateLimiter) Wait(size int) {
	if l == nil || size <= 0 {
		return
	}

	need := float64(size)
	for {
		l.mu.Lock()
		if l.rate <= 0 {
			l.mu.Unlock()
			return
		}
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		if elapsed > 0 {
			l.available += elapsed * l.rate
			if l.available > l.capacity {
				l.available = l.capacity
			}
			l.last = now
		}
		if l.available >= need {
			l.available -= need
			l.mu.Unlock()
			return
		}
		missing := need - l.available
		wait := time.Duration(missing / l.rate * float64(time.Second))
		l.mu.Unlock()

		if wait <= 0 {
			wait = time.Millisecond
		}
		time.Sleep(wait)
	}
}
