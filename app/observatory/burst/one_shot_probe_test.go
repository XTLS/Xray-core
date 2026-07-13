package burst

import (
	"context"
	stderrors "errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
)

func requireObservationUpdate(t *testing.T, updates <-chan struct{}) {
	t.Helper()
	select {
	case _, open := <-updates:
		if !open {
			t.Fatal("observation update subscription closed unexpectedly")
		}
	default:
		t.Fatal("observer did not publish a result update")
	}
}

func requireNoObservationUpdate(t *testing.T, updates <-chan struct{}) {
	t.Helper()
	select {
	case _, open := <-updates:
		if open {
			t.Fatal("observer published an unexpected result update")
		}
	default:
	}
}

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
	var tagAccess sync.Mutex
	activeTags := make(map[string]int)
	concurrentSample := false
	updates, unsubscribe := observer.SubscribeObservationUpdates()
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
	requireObservationUpdate(t, updates)
	requireNoObservationUpdate(t, updates)

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
	if err := observer.ProbeOutbounds(context.Background(), tags, 1, 1); err != nil {
		t.Fatal(err)
	}
	requireObservationUpdate(t, updates)
	requireNoObservationUpdate(t, updates)
	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	for _, tag := range tags {
		if got := healthPing.Results[tag].getStatistics().All; got != 1 {
			t.Fatalf("replacement samples for %q = %d, want 1", tag, got)
		}
	}
}

func TestOneShotProbePublishesEmptySnapshot(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	staleResult := NewHealthPingResult(1, time.Hour)
	staleResult.Put(time.Second)
	healthPing.Results = map[string]*HealthPingRTTS{"stale": staleResult}
	observer := &Observer{
		config: &Config{},
		hp:     healthPing,
		ohm:    &probeTestManager{handlers: map[string]outbound.Handler{}},
	}
	defer observer.Close()
	updates, unsubscribe := observer.SubscribeObservationUpdates()
	defer unsubscribe()

	if err := observer.ProbeOutbounds(context.Background(), nil, 1, 1); err != nil {
		t.Fatal(err)
	}
	requireObservationUpdate(t, updates)
	requireNoObservationUpdate(t, updates)
	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	if len(healthPing.Results) != 0 {
		t.Fatalf("empty batch retained %d stale results", len(healthPing.Results))
	}
}

func TestObserverReportsBatchProbeDeadline(t *testing.T) {
	tags := []string{"proxy-a", "proxy-b", "proxy-c", "proxy-d", "proxy-e"}
	manager := &probeTestManager{handlers: make(map[string]outbound.Handler, len(tags))}
	for _, tag := range tags {
		manager.handlers[tag] = &probeTestHandler{tag: tag}
	}
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.Settings.Timeout = 2 * time.Second
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()

	withDuplicate := append(append([]string{}, tags...), "proxy-a")
	if got, err := observer.ProbeOutboundsDeadline(withDuplicate, 2, 3); err != nil || got != 18*time.Second {
		t.Fatalf("batch deadline = %v, %v; want 18s, nil", got, err)
	}
	healthPing.Settings.Connectivity = "https://example.com/generate_204"
	if got, err := observer.ProbeOutboundsDeadline(withDuplicate, 2, 3); err != nil || got != 36*time.Second {
		t.Fatalf("batch deadline with connectivity = %v, %v; want 36s, nil", got, err)
	}
	healthPing.Settings.Connectivity = ""
	if got, err := observer.ProbeOutboundsDeadline(tags, 10, 3); err != nil || got != 6*time.Second {
		t.Fatalf("single-wave batch deadline = %v, %v; want 6s, nil", got, err)
	}
	if got, err := observer.ProbeOutboundsDeadline(nil, 2, 3); err != nil || got != 0 {
		t.Fatalf("empty batch deadline = %v, %v; want 0, nil", got, err)
	}
	if _, err := observer.ProbeOutboundsDeadline(tags, 0, 1); err == nil {
		t.Fatal("zero concurrency did not return an error")
	}
	if _, err := observer.ProbeOutboundsDeadline(tags, 1, 0); err == nil {
		t.Fatal("zero samples did not return an error")
	}

	healthPing.Settings.Timeout = time.Duration(math.MaxInt64/2 + 1)
	if _, err := observer.ProbeOutboundsDeadline(tags[:2], 1, 1); err == nil {
		t.Fatal("overflowing batch deadline did not return an error")
	}
	var measures atomic.Int32
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		measures.Add(1)
		return time.Millisecond, nil
	}
	if err := observer.ProbeOutbounds(context.Background(), tags[:2], 1, 1); err == nil {
		t.Fatal("batch with an overflowing deadline started probing")
	}
	if got := measures.Load(); got != 0 {
		t.Fatalf("overflowing batch started %d measurements, want none", got)
	}
}

func TestObserverRejectsUnboundedBatchWork(t *testing.T) {
	workerTags := make([]string, maxBatchProbeWorkers+1)
	manager := &probeTestManager{handlers: make(map[string]outbound.Handler, len(workerTags))}
	for i := range workerTags {
		workerTags[i] = fmt.Sprintf("proxy-%d", i)
		manager.handlers[workerTags[i]] = &probeTestHandler{tag: workerTags[i]}
	}
	healthPing := NewHealthPing(context.Background(), nil, nil)
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()

	if _, err := observer.ProbeOutboundsDeadline(
		workerTags[:1],
		1,
		maxBatchProbeSamplesPerOutbound+1,
	); err == nil || !strings.Contains(err.Error(), "sample count exceeds") {
		t.Fatalf("sample limit error = %v", err)
	}
	if _, err := observer.ProbeOutboundsDeadline(
		workerTags,
		len(workerTags),
		1,
	); err == nil || !strings.Contains(err.Error(), "active-worker limit") {
		t.Fatalf("worker limit error = %v", err)
	}

	retainedTags := make([]string, maxBatchProbeRetainedMeasurements/maxBatchProbeSamplesPerOutbound+1)
	for i := range retainedTags {
		retainedTags[i] = fmt.Sprintf("retained-%d", i)
		manager.handlers[retainedTags[i]] = &probeTestHandler{tag: retainedTags[i]}
	}
	if _, err := observer.ProbeOutboundsDeadline(
		retainedTags,
		1,
		maxBatchProbeSamplesPerOutbound,
	); err == nil || !strings.Contains(err.Error(), "retained-measurement limit") {
		t.Fatalf("retained measurement limit error = %v", err)
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

func TestOneShotProbePreservesSnapshotWhenNetworkIsUnavailable(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.Settings.Connectivity = "://invalid-connectivity-url"
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		return 0, stderrors.New("unreachable")
	}
	previous := NewHealthPingResult(1, time.Hour)
	previous.Put(42 * time.Millisecond)
	healthPing.Results = map[string]*HealthPingRTTS{"previous": previous}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()
	updates, unsubscribe := observer.SubscribeObservationUpdates()
	defer unsubscribe()

	err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1)
	if !stderrors.Is(err, extension.ErrObservatoryProbeNetworkUnavailable) {
		t.Fatalf("probe error = %v, want network-unavailable error", err)
	}
	requireNoObservationUpdate(t, updates)
	healthPing.access.Lock()
	defer healthPing.access.Unlock()
	if healthPing.Results["previous"] != previous || len(healthPing.Results) != 1 {
		t.Fatal("network-unavailable batch replaced the previous complete snapshot")
	}
}

func TestObserverSubscriberCanCloseAfterPublication(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	updates, unsubscribe := observer.SubscribeObservationUpdates()
	defer unsubscribe()

	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err != nil {
		t.Fatal(err)
	}
	requireObservationUpdate(t, updates)
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, open := <-updates; open {
		t.Fatal("observer close left the update subscription open")
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

func TestObserverDropsManualCheckDuringBatch(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.Settings.Destination = "://invalid-probe-url"
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	healthPing.measure = func(ctx context.Context, _ string) (time.Duration, error) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
			return 20 * time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	defer observer.Close()

	probeDone := make(chan error, 1)
	go func() {
		probeDone <- observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1)
	}()
	<-started
	observer.Check([]string{"manual"})
	healthPing.access.Lock()
	_, manualResult := healthPing.Results["manual"]
	healthPing.access.Unlock()
	if manualResult {
		t.Fatal("manual check mutated results while a batch was running")
	}
	close(release)
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}
}

func TestUnreadObservationUpdatesDoNotBlockProbeCompletion(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	healthPing.measure = func(context.Context, string) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}
	manager := &probeTestManager{handlers: map[string]outbound.Handler{
		"proxy-a": &probeTestHandler{tag: "proxy-a"},
	}}
	observer := &Observer{config: &Config{}, hp: healthPing, ohm: manager}
	healthPing.onUpdate = observer.updates.NotifyObservationUpdate
	defer observer.Close()
	updates, unsubscribe := observer.SubscribeObservationUpdates()
	defer unsubscribe()

	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := observer.ProbeOutbounds(context.Background(), []string{"proxy-a"}, 1, 1); err != nil {
		t.Fatal(err)
	}

	// Both successful batches complete while the single-slot notification
	// channel is deliberately left unread. Their signals are coalesced.
	requireObservationUpdate(t, updates)
	requireNoObservationUpdate(t, updates)
}
