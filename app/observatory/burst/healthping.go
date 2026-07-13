package burst

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/routing"
)

// HealthPingSettings holds settings for health Checker
type HealthPingSettings struct {
	Destination   string        `json:"destination"`
	Connectivity  string        `json:"connectivity"`
	Interval      time.Duration `json:"interval"`
	SamplingCount int           `json:"sampling"`
	Timeout       time.Duration `json:"timeout"`
	HttpMethod    string        `json:"httpMethod"`
}

// HealthPing is the health checker for balancers
type HealthPing struct {
	ctx           context.Context
	cancelCtx     context.CancelFunc
	cancelPending atomic.Pointer[context.CancelFunc]
	dispatcher    routing.Dispatcher
	access        sync.Mutex
	ticker        *time.Ticker

	Settings *HealthPingSettings
	Results  map[string]*HealthPingRTTS
	onUpdate func()
	measure  func(context.Context, string) (time.Duration, error)
}

// NewHealthPing creates a new HealthPing with settings
func NewHealthPing(ctx context.Context, dispatcher routing.Dispatcher, config *HealthPingConfig) *HealthPing {
	settings := &HealthPingSettings{}
	if config != nil {

		var httpMethod string
		if config.HttpMethod == "" {
			httpMethod = "HEAD"
		} else {
			httpMethod = strings.TrimSpace(config.HttpMethod)
		}

		settings = &HealthPingSettings{
			Connectivity:  strings.TrimSpace(config.Connectivity),
			Destination:   strings.TrimSpace(config.Destination),
			Interval:      time.Duration(config.Interval),
			SamplingCount: int(config.SamplingCount),
			Timeout:       time.Duration(config.Timeout),
			HttpMethod:    httpMethod,
		}
	}
	if settings.Destination == "" {
		// Destination URL, need 204 for success return default to chromium
		// https://github.com/chromium/chromium/blob/main/components/safety_check/url_constants.cc#L10
		// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/safety_check/url_constants.cc#10
		settings.Destination = "https://connectivitycheck.gstatic.com/generate_204"
	}
	if settings.Interval == 0 {
		settings.Interval = 1 * time.Minute
	} else if settings.Interval < 10*time.Second {
		errors.LogWarning(ctx, "health check interval is too small, 10s is applied")
		settings.Interval = 10 * time.Second
	}
	if settings.SamplingCount <= 0 {
		settings.SamplingCount = 10
	}
	if settings.Timeout <= 0 {
		// results are saved after all health pings finish,
		// a larger timeout could possibly makes checks run longer
		settings.Timeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(ctx)
	return &HealthPing{
		ctx:        ctx,
		cancelCtx:  cancel,
		dispatcher: dispatcher,
		Settings:   settings,
		Results:    nil,
	}
}

// StartScheduler implements the HealthChecker
func (h *HealthPing) StartScheduler(selector func() ([]string, error)) {
	if h.ticker != nil {
		return
	}
	interval := h.Settings.Interval * time.Duration(h.Settings.SamplingCount)
	ticker := time.NewTicker(interval)
	h.ticker = ticker

	// init run to get a fast check result
	go func() {
		tags, err := selector()
		if err != nil {
			errors.LogWarning(h.ctx, "error select outbounds for initial health check: ", err)
			return
		}
		h.Check(tags)
	}()

	go func() {
		for {
			go func() {
				tags, err := selector()
				if err != nil {
					errors.LogWarning(h.ctx, "error select outbounds for scheduled health check: ", err)
					return
				}
				subCtx, cancel := context.WithCancel(h.ctx)
				old := h.cancelPending.Swap(&cancel)
				if old != nil {
					errors.LogDebug(h.ctx, "scheduled health check not finished before next round, canceling previous one")
					(*old)()
				}
				h.doCheck(subCtx, tags, interval, h.Settings.SamplingCount)
				h.cancelPending.CompareAndSwap(&cancel, nil)
				h.Cleanup(tags)
			}()
			select {
			case <-ticker.C:
				continue
			case <-h.ctx.Done():
				return
			}
		}
	}()
}

// StopScheduler implements the HealthChecker
func (h *HealthPing) StopScheduler() {
	if h.ticker == nil {
		return
	}
	h.ticker.Stop()
	h.ticker = nil
	h.cancelCtx()
}

// Check implements the HealthChecker
func (h *HealthPing) Check(tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	errors.LogInfo(h.ctx, "perform one-time health check for tags ", tags)
	h.doCheck(h.ctx, tags, 0, 1)
	return nil
}

// probeOutbounds executes a finite batch prepared by Observer. The observer
// owns validation and overlap exclusion; keeping those policy decisions at the
// public API boundary leaves HealthPing responsible only for measurements and
// result publication.
func (h *HealthPing) probeOutbounds(ctx context.Context, tags []string, maxConcurrency, samples int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.ctx.Err(); err != nil {
		return err
	}
	if len(tags) == 0 {
		h.replaceResults(make(map[string]*HealthPingRTTS))
		h.notifyUpdate()
		return nil
	}

	// The caller controls the lifetime of a batch, but it does not own Xray's
	// instance context. Keep the health checker's context as the value-bearing
	// parent required by tagged.Dialer and bridge caller cancellation into it.
	runCtx, cancel := context.WithCancel(h.ctx)
	stopCallerCancellation := context.AfterFunc(ctx, cancel)
	defer func() {
		stopCallerCancellation()
		cancel()
	}()

	h.replaceResults(make(map[string]*HealthPingRTTS, len(tags)))

	workerCount := min(maxConcurrency, len(tags))
	tasks := make(chan string)
	var networkUnavailable atomic.Bool
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for tag := range tasks {
				for range samples {
					delay, err := h.measureOutbound(runCtx, tag)
					if err != nil {
						if runCtx.Err() != nil {
							return
						}
						connectivityOK := h.checkConnectivity(runCtx)
						if runCtx.Err() != nil {
							return
						}
						if !connectivityOK {
							errors.LogWarning(h.ctx, "network is down while probing ", tag)
							networkUnavailable.Store(true)
							cancel()
							return
						} else {
							errors.LogWarning(h.ctx, fmt.Sprintf(
								"error ping %s with %s: %s",
								h.Settings.Destination,
								tag,
								err,
							))
						}
						delay = rttFailed
					}
					h.putProbeResult(tag, delay, samples)
				}
			}
		}()
	}

	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		defer close(tasks)
		for _, tag := range tags {
			select {
			case tasks <- tag:
			case <-runCtx.Done():
				return
			}
		}
	}()

	workers.Wait()
	<-feedDone
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.ctx.Err(); err != nil {
		return err
	}
	if networkUnavailable.Load() {
		return extension.ErrObservatoryProbeNetworkUnavailable
	}
	if err := runCtx.Err(); err != nil {
		return err
	}
	return nil
}

func (h *HealthPing) measureOutbound(ctx context.Context, tag string) (time.Duration, error) {
	if h.measure != nil {
		return h.measure(ctx, tag)
	}
	client := newPingClient(
		ctx,
		h.dispatcher,
		h.Settings.Destination,
		h.Settings.Timeout,
		tag,
	)
	return client.MeasureDelayContext(ctx, h.Settings.HttpMethod)
}

func (h *HealthPing) replaceResults(replacements map[string]*HealthPingRTTS) {
	h.access.Lock()
	h.Results = replacements
	h.access.Unlock()
}

func (h *HealthPing) putProbeResult(tag string, delay time.Duration, samples int) {
	h.access.Lock()
	result := h.Results[tag]
	if result == nil {
		// One-shot samples do not expire because the containing probe process is
		// disposable and the completed snapshot is its final output.
		result = NewHealthPingResult(samples, 0)
		h.Results[tag] = result
	}
	result.Put(delay)
	h.access.Unlock()
	h.notifyUpdate()
}

func (h *HealthPing) notifyUpdate() {
	if h.onUpdate != nil {
		h.onUpdate()
	}
}

type rtt struct {
	handler string
	value   time.Duration
}

// doCheck performs the 'rounds' amount checks in given 'duration'. You should make
// sure all tags are valid for current balancer
// cancel ctx will stop all pending checks
func (h *HealthPing) doCheck(ctx context.Context, tags []string, duration time.Duration, rounds int) {
	count := len(tags) * rounds
	if count == 0 {
		return
	}
	ch := make(chan *rtt, count)
	timers := make([]*time.Timer, 0, count)
	for _, tag := range tags {
		handler := tag
		client := newPingClient(
			h.ctx,
			h.dispatcher,
			h.Settings.Destination,
			h.Settings.Timeout,
			handler,
		)
		for i := 0; i < rounds; i++ {
			delay := time.Duration(0)
			if duration > 0 {
				delay = time.Duration(dice.RollInt63n(int64(duration)))
			}
			timers = append(timers, time.AfterFunc(delay, func() {
				errors.LogDebug(h.ctx, "checking ", handler)
				delay, err := client.MeasureDelay(h.Settings.HttpMethod)
				if err == nil {
					ch <- &rtt{
						handler: handler,
						value:   delay,
					}
					return
				}
				if !h.checkConnectivity(ctx) {
					errors.LogWarning(h.ctx, "network is down")
					ch <- &rtt{
						handler: handler,
						value:   0,
					}
					return
				}
				errors.LogWarning(h.ctx, fmt.Sprintf(
					"error ping %s with %s: %s",
					h.Settings.Destination,
					handler,
					err,
				))
				ch <- &rtt{
					handler: handler,
					value:   rttFailed,
				}
			}))
		}
	}
	for i := 0; i < count; i++ {
		select {
		case rtt := <-ch:
			if rtt.value > 0 {
				// should not put results when network is down
				h.PutResult(rtt.handler, rtt.value)
			}
		case <-ctx.Done():
			for _, timer := range timers {
				timer.Stop()
			}
			return
		}
	}
}

// PutResult put a ping rtt to results
func (h *HealthPing) PutResult(tag string, rtt time.Duration) {
	h.access.Lock()
	if h.Results == nil {
		h.Results = make(map[string]*HealthPingRTTS)
	}
	r, ok := h.Results[tag]
	if !ok {
		// validity is 2 times to sampling period, since the check are
		// distributed in the time line randomly, in extreme cases,
		// Previous checks are distributed on the left, and later ones
		// on the right
		validity := h.Settings.Interval * time.Duration(h.Settings.SamplingCount) * 2
		r = NewHealthPingResult(h.Settings.SamplingCount, validity)
		h.Results[tag] = r
	}
	r.Put(rtt)
	h.access.Unlock()
	h.notifyUpdate()
}

// Cleanup removes results of removed handlers,
// tags should be all valid tags of the Balancer now
func (h *HealthPing) Cleanup(tags []string) {
	h.access.Lock()
	changed := false
	for tag := range h.Results {
		found := false
		for _, v := range tags {
			if tag == v {
				found = true
				break
			}
		}
		if !found {
			delete(h.Results, tag)
			changed = true
		}
	}
	h.access.Unlock()
	if changed {
		h.notifyUpdate()
	}
}

// checkConnectivity checks the network connectivity, it returns
// true if network is good or "connectivity check url" not set
func (h *HealthPing) checkConnectivity(ctx context.Context) bool {
	if h.Settings.Connectivity == "" {
		return true
	}
	tester := newDirectPingClient(
		h.Settings.Connectivity,
		h.Settings.Timeout,
	)
	if _, err := tester.MeasureDelayContext(ctx, h.Settings.HttpMethod); err != nil {
		return false
	}
	return true
}
