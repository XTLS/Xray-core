package burst

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestInitialCheckWindow(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		0:                0 + initialCheckSpread,
		10 * time.Second: 10 * time.Second,
		8 * time.Hour:    initialCheckSpread,
		60 * time.Second: 60 * time.Second,
	}
	for in, want := range cases {
		if got := initialCheckWindow(in); got != want {
			t.Errorf("initialCheckWindow(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestTagFamily(t *testing.T) {
	cases := map[string]string{
		"cf_12":   "cf",
		"bu_a_b":  "bu",
		"reserve": "reserve",
		"_x":      "_x",
	}
	for in, want := range cases {
		if got := tagFamily(in); got != want {
			t.Errorf("tagFamily(%q) = %q, want %q", in, got, want)
		}
	}
}

// probe records concurrency of fake measurements.
type probe struct {
	mu        sync.Mutex
	cur, peak int
	famCur    map[string]int
	famPeak   map[string]int
	starts    []time.Time
}

func newProbe() *probe {
	return &probe{famCur: map[string]int{}, famPeak: map[string]int{}}
}

func (p *probe) measure(hold time.Duration) func(string, *pingClient) (time.Duration, error) {
	return func(tag string, _ *pingClient) (time.Duration, error) {
		f := tagFamily(tag)
		p.mu.Lock()
		p.cur++
		p.famCur[f]++
		if p.cur > p.peak {
			p.peak = p.cur
		}
		if p.famCur[f] > p.famPeak[f] {
			p.famPeak[f] = p.famCur[f]
		}
		p.starts = append(p.starts, time.Now())
		p.mu.Unlock()
		time.Sleep(hold)
		p.mu.Lock()
		p.cur--
		p.famCur[f]--
		p.mu.Unlock()
		return 10 * time.Millisecond, nil
	}
}

func testHealthPing(p *probe, hold time.Duration) *HealthPing {
	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Destination:   "http://127.0.0.1/",
		Interval:      int64(time.Minute),
		SamplingCount: 1,
		Timeout:       int64(time.Second),
	})
	h.measure = p.measure(hold)
	return h
}

func makeTags() []string {
	var tags []string
	fams := map[string]int{"cf": 40, "f": 20, "gc": 10, "bu": 10, "aws": 6}
	for f, n := range fams {
		for i := 0; i < n; i++ {
			tags = append(tags, fmt.Sprintf("%s_%d", f, i))
		}
	}
	return append(tags, "reserve")
}

func checkLimits(t *testing.T, p *probe, total int) {
	t.Helper()
	if len(p.starts) != total {
		t.Fatalf("measured %d, want %d", len(p.starts), total)
	}
	if p.peak > maxParallelPings {
		t.Errorf("global peak %d > %d", p.peak, maxParallelPings)
	}
	for f, n := range p.famPeak {
		if n > defaultStartCheck {
			t.Errorf("family %s peak %d > %d", f, n, defaultStartCheck)
		}
	}
}

func TestDoCheckImmediateIsLimited(t *testing.T) {
	p := newProbe()
	h := testHealthPing(p, 20*time.Millisecond)
	tags := makeTags()
	done := make(chan struct{})
	go func() { h.doCheck(context.Background(), tags, 0, 1); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("doCheck hung")
	}
	checkLimits(t, p, len(tags))
	if p.famPeak["cf"] != defaultStartCheck {
		t.Errorf("cf peak %d, expected the limit %d to be reached", p.famPeak["cf"], defaultStartCheck)
	}
	if len(h.Results) != len(tags) {
		t.Errorf("results for %d tags, want %d", len(h.Results), len(tags))
	}
}

func TestDoCheckSpread(t *testing.T) {
	p := newProbe()
	h := testHealthPing(p, time.Millisecond)
	tags := makeTags()
	window := 300 * time.Millisecond
	begin := time.Now()
	h.doCheck(context.Background(), tags, window, 1)
	checkLimits(t, p, len(tags))
	first, last := p.starts[0], p.starts[0]
	for _, s := range p.starts {
		if s.Before(first) {
			first = s
		}
		if s.After(last) {
			last = s
		}
	}
	if last.Sub(first) < window/4 {
		t.Errorf("starts not spread: span %v", last.Sub(first))
	}
	if last.Sub(begin) > window+time.Second {
		t.Errorf("last start %v after begin, window %v", last.Sub(begin), window)
	}
}

func TestDoCheckCancelWhileWaiting(t *testing.T) {
	p := newProbe()
	h := testHealthPing(p, 200*time.Millisecond)
	tags := makeTags()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.doCheck(ctx, tags, 0, 1); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("doCheck did not return after cancel")
	}
	// in-flight pings finish and release; all slots must be free afterwards
	deadline := time.Now().Add(5 * time.Second)
	for len(h.limiter.global) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(h.limiter.global); n != 0 {
		t.Errorf("global semaphore leaked %d slots", n)
	}
	h.limiter.mu.Lock()
	for f, sem := range h.limiter.families {
		if len(sem) != 0 {
			t.Errorf("family %s leaked %d slots", f, len(sem))
		}
	}
	h.limiter.mu.Unlock()
	p.mu.Lock()
	started := len(p.starts)
	p.mu.Unlock()
	if started >= len(tags) {
		t.Errorf("cancel did not stop pending pings: %d started", started)
	}
}

func TestStartCheckSetting(t *testing.T) {
	cases := map[int32]int{0: defaultStartCheck, -1: defaultStartCheck, 2: 2, 10: 10}
	for in, want := range cases {
		h := NewHealthPing(context.Background(), nil, &HealthPingConfig{StartCheck: in})
		if h.Settings.StartCheck != want || h.limiter.perFamily != want {
			t.Errorf("startCheck %d: settings %d, limiter %d, want %d",
				in, h.Settings.StartCheck, h.limiter.perFamily, want)
		}
	}
}

func TestDoCheckStartCheckLimit(t *testing.T) {
	p := newProbe()
	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Interval:   int64(time.Minute),
		Timeout:    int64(time.Second),
		StartCheck: 2,
	})
	h.measure = p.measure(20 * time.Millisecond)
	tags := makeTags()
	h.doCheck(context.Background(), tags, 0, 1)
	for f, n := range p.famPeak {
		if n > 2 {
			t.Errorf("family %s peak %d > startCheck 2", f, n)
		}
	}
	if p.famPeak["cf"] != 2 {
		t.Errorf("cf peak %d, want 2", p.famPeak["cf"])
	}
}

func TestDisableScheduler(t *testing.T) {
	DisableScheduler = true
	defer func() { DisableScheduler = false }()
	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{Interval: int64(time.Minute)})
	called := false
	h.StartScheduler(func() ([]string, error) { called = true; return []string{"cf_1"}, nil })
	if h.ticker != nil || called {
		t.Error("scheduler started while disabled")
	}
	h.StopScheduler()
}
