package burst

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/outbound"
)

func TestOneShotProbeBoundsConcurrencyAndSamplesEveryTag(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	tags := []string{"proxy-a", "proxy-b", "proxy-c"}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{}}
	for _, tag := range tags {
		manager.handlers[tag] = &probeTestHandler{tag: tag}
	}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()
	staleResult := NewHealthPingResult(1, time.Hour)
	staleResult.Put(time.Second)
	healthPing.Results = map[string]*HealthPingRTTS{"stale": staleResult}

	var active atomic.Int32
	var peak atomic.Int32
	var updates atomic.Int32
	var expectedSamples atomic.Int32
	var incompletePublication atomic.Bool
	var tagAccess sync.Mutex
	activeTags := make(map[string]int)
	concurrentSample := false
	expectedSamples.Store(3)
	unsubscribe := observer.SubscribeObservationUpdates(func() {
		healthPing.access.Lock()
		defer healthPing.access.Unlock()
		for _, tag := range tags {
			result := healthPing.Results[tag]
			if result == nil || result.getStatistics().All != int(expectedSamples.Load()) {
				incompletePublication.Store(true)
			}
		}
		updates.Add(1)
	})
	defer unsubscribe()
	healthPing.measure = func(ctx context.Context, tag string) (time.Duration, error) {
		current := active.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		tagAccess.Lock()
		activeTags[tag]++
		if activeTags[tag] > 1 {
			concurrentSample = true
		}
		tagAccess.Unlock()
		defer func() {
			tagAccess.Lock()
			activeTags[tag]--
			tagAccess.Unlock()
			active.Add(-1)
		}()

		select {
		case <-time.After(10 * time.Millisecond):
			return 20 * time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}

	probeTags := append(append([]string{}, tags...), "proxy-a")
	if err := observer.ProbeOutbounds(context.Background(), probeTags, 2, 3); err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak probes = %d, want 2", got)
	}
	if concurrentSample {
		t.Fatal("samples for the same outbound ran concurrently")
	}
	if got := updates.Load(); got != 1 {
		t.Fatalf("result updates = %d, want one atomic publication", got)
	}
	if incompletePublication.Load() {
		t.Fatal("observer was notified before the complete batch was published")
	}

	healthPing.access.Lock()
	if _, found := healthPing.Results["stale"]; found {
		healthPing.access.Unlock()
		t.Fatal("completed batch retained a result outside the requested tags")
	}
	for _, tag := range tags {
		result := healthPing.Results[tag]
		if result == nil {
			healthPing.access.Unlock()
			t.Fatalf("missing result for %q", tag)
		}
		if got := result.getStatistics().All; got != 3 {
			healthPing.access.Unlock()
			t.Fatalf("samples for %q = %d, want 3", tag, got)
		}
	}
	healthPing.access.Unlock()

	// A later batch must replace, rather than accumulate with, prior samples.
	expectedSamples.Store(1)
	if err := observer.ProbeOutbounds(context.Background(), tags, 1, 1); err != nil {
		t.Fatal(err)
	}
	if got := updates.Load(); got != 2 {
		t.Fatalf("result updates after replacement = %d, want 2", got)
	}
	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	for _, tag := range tags {
		if got := healthPing.Results[tag].getStatistics().All; got != 1 {
			t.Fatalf("replacement samples for %q = %d, want 1", tag, got)
		}
	}
}

func TestOneShotProbeRecordsFailedSamples(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		return 0, stderrors.New("unreachable")
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()

	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 2); err != nil {
		t.Fatal(err)
	}
	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	stats := healthPing.Results["proxy-a"].getStatistics()
	if stats.All != 2 || stats.Fail != 2 {
		t.Fatalf("failed sample statistics = all %d, fail %d; want 2, 2", stats.All, stats.Fail)
	}
}

func TestObserverUpdateListenerCanCloseAfterPublication(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	listenerDone := make(chan error, 1)
	observer.SubscribeObservationUpdates(func() {
		listenerDone <- observer.Close()
	})

	probeDone := make(chan error, 1)
	go func() {
		probeDone <- observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1)
	}()
	select {
	case err := <-listenerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("update listener deadlocked while closing the observer")
	}
	select {
	case err := <-probeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not return after its update listener closed the observer")
	}
}

func TestOneShotProbeHonorsCancellation(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	defer healthPing.cancelCtx()
	previous := NewHealthPingResult(1, time.Hour)
	previous.Put(42 * time.Millisecond)
	healthPing.Results = map[string]*HealthPingRTTS{"proxy-a": previous}
	started := make(chan struct{})
	var startedOnce sync.Once
	healthPing.measure = func(ctx context.Context, _ string) (time.Duration, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		return 0, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- healthPing.ProbeOutbounds(ctx, []string{"proxy-a", "proxy-b"}, 2, 2)
	}()
	<-started
	cancel()

	select {
	case err := <-done:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled probe batch did not return")
	}

	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	if healthPing.Results["proxy-a"] != previous {
		t.Fatal("cancelled probe replaced the previous complete result with a partial batch")
	}
}

func TestOneShotProbeRetainsObserverContext(t *testing.T) {
	type observerContextKey struct{}
	contextValue := new(int)
	healthPing := NewHealthPing(
		context.WithValue(context.Background(), observerContextKey{}, contextValue),
		nil,
		nil,
	)
	defer healthPing.cancelCtx()
	healthPing.measure = func(ctx context.Context, _ string) (time.Duration, error) {
		if got := ctx.Value(observerContextKey{}); got != contextValue {
			return 0, stderrors.New("observer context value is missing")
		}
		return 20 * time.Millisecond, nil
	}

	if err := healthPing.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err != nil {
		t.Fatal(err)
	}
	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	stats := healthPing.Results["proxy-a"].getStatistics()
	if stats.All != 1 || stats.Fail != 0 {
		t.Fatalf("probe statistics = all %d, fail %d; want 1, 0", stats.All, stats.Fail)
	}
}

type probeTestHandler struct {
	outbound.Handler
	tag string
}

func (h *probeTestHandler) Tag() string { return h.tag }

type probeTestManager struct {
	outbound.Manager
	handlers map[string]outbound.Handler
}

func (m *probeTestManager) GetHandler(tag string) outbound.Handler { return m.handlers[tag] }

func TestObserverRejectsMissingAndScheduledOutbounds(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	var measures atomic.Int32
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		measures.Add(1)
		return time.Millisecond, nil
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()

	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a", "missing"}, 1, 1); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing handler error = %v", err)
	}
	if got := measures.Load(); got != 0 {
		t.Fatalf("started %d probes before validating every outbound tag", got)
	}

	observer.config.SubjectSelector = []string{"proxy"}
	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err == nil || !strings.Contains(err.Error(), "scheduled selectors") {
		t.Fatalf("scheduled observer error = %v", err)
	}
}

func TestObserverRejectsOverlapAndCloseCancelsProbe(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	started := make(chan struct{})
	var startedOnce sync.Once
	healthPing.measure = func(ctx context.Context, _ string) (time.Duration, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		return 0, ctx.Err()
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}

	probeDone := make(chan error, 1)
	go func() {
		probeDone <- observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1)
	}()
	<-started

	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("overlapping probe error = %v", err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- observer.Close() }()
	select {
	case err := <-probeDone:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("probe error after close = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer close did not cancel the probe")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer close did not wait for probe shutdown")
	}

	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed observer error = %v", err)
	}
}
