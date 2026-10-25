package burst

import (
	"context"
	"strings"
	"sync"
	"time"
)

const (
	// initialCheckSpread caps the window over which the initial health check
	// of all outbounds is spread, instead of pinging everything at once.
	initialCheckSpread = 60 * time.Second
	// maxParallelPings limits concurrent measurements across the whole HealthPing.
	maxParallelPings = 32
	// maxParallelPerFamily limits concurrent measurements per tag family.
	// A family is the tag prefix before the first '_' ("cf_1" -> "cf").
	maxParallelPerFamily = 4
)

// initialCheckWindow returns the spread window for the initial run:
// min(total, initialCheckSpread), where total = interval * sampling.
func initialCheckWindow(total time.Duration) time.Duration {
	if total <= 0 || total > initialCheckSpread {
		return initialCheckSpread
	}
	return total
}

// tagFamily returns the family of an outbound tag: the part before the
// first '_'. Tags without '_' form a family of their own.
func tagFamily(tag string) string {
	if i := strings.IndexByte(tag, '_'); i > 0 {
		return tag[:i]
	}
	return tag
}

// pingLimiter bounds concurrent pings globally and per tag family.
type pingLimiter struct {
	global    chan struct{}
	perFamily int

	mu       sync.Mutex
	families map[string]chan struct{}
}

func newPingLimiter(global, perFamily int) *pingLimiter {
	return &pingLimiter{
		global:    make(chan struct{}, global),
		perFamily: perFamily,
		families:  make(map[string]chan struct{}),
	}
}

func (l *pingLimiter) family(tag string) chan struct{} {
	f := tagFamily(tag)
	l.mu.Lock()
	defer l.mu.Unlock()
	sem, ok := l.families[f]
	if !ok {
		sem = make(chan struct{}, l.perFamily)
		l.families[f] = sem
	}
	return sem
}

// acquire takes a family slot, then a global slot, so a goroutine never holds
// a global slot while waiting for its family. It returns a release func, or
// false if ctx was canceled while waiting (nothing is held in that case).
func (l *pingLimiter) acquire(ctx context.Context, tag string) (func(), bool) {
	fam := l.family(tag)
	select {
	case fam <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	select {
	case l.global <- struct{}{}:
	case <-ctx.Done():
		<-fam
		return nil, false
	}
	return func() {
		<-l.global
		<-fam
	}, true
}
