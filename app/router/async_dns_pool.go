package router

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	asyncDNSOverlayPoolEnv  = "XRAY_ASYNC_DNS_OVERLAY_ENDPOINTS_JSON"
	asyncDNSPoolMaxAttempts = 6
)

var asyncDNSOverlayPrefix = netip.MustParsePrefix("100.64.0.0/10")

type asyncDNSEndpointState struct {
	endpoint      string
	failures      uint8
	cooldownUntil time.Time
	metrics       *asyncDNSPoolEndpointCounters
}

type asyncDNSEndpointCandidate struct {
	endpoint    string
	knownFailed bool
}

// The fixed-size pool is operator transport configuration, never owner JSON.
// Its allowlist is immutable; passive health state uses a separate mutex from L1.
type asyncDNSEndpointPool struct {
	mu       sync.Mutex
	states   []asyncDNSEndpointState
	allowed  map[string]struct{}
	next     int
	identity string
}

func readAsyncDNSOverlayPool(overlay, token string) (*asyncDNSEndpointPool, error) {
	raw, configured := os.LookupEnv(asyncDNSOverlayPoolEnv)
	if !configured || raw == "" {
		return nil, nil
	}
	var endpoints []string
	if len(raw) > 4096 || json.Unmarshal([]byte(raw), &endpoints) != nil || len(endpoints) < 2 || len(endpoints) > 6 {
		return nil, errors.New("async DNS overlay pool requires a JSON array of 2..6 endpoints within 4096 bytes")
	}
	if overlay == "" || endpoints[0] != overlay || token == "" {
		return nil, errors.New("async DNS overlay pool requires its first endpoint as the singular pin and a bearer token")
	}
	p := &asyncDNSEndpointPool{allowed: make(map[string]struct{}, len(endpoints))}
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || u.EscapedPath() != "/v1/classify" {
			return nil, errors.New("async DNS overlay pool requires exact HTTP private IP endpoints at /v1/classify")
		}
		ip, ipErr := netip.ParseAddr(u.Hostname())
		port, portErr := strconv.Atoi(u.Port())
		if ipErr != nil || ip.Zone() != "" || ip.IsLoopback() || !(ip.IsPrivate() || asyncDNSOverlayPrefix.Contains(ip)) || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() || u.Hostname() != ip.String() {
			return nil, errors.New("async DNS overlay pool requires canonical private IPs and explicit ports")
		}
		if _, duplicate := p.allowed[endpoint]; duplicate {
			return nil, errors.New("async DNS overlay pool endpoints must be distinct")
		}
		p.allowed[endpoint] = struct{}{}
		p.states = append(p.states, asyncDNSEndpointState{endpoint: endpoint, metrics: &asyncDNSPoolEndpointCounters{}})
	}
	// Reordering and passive failover do not invalidate persisted classifications.
	// Membership changes do; the owner ID separately binds resolver/GeoIP semantics.
	canonical := append([]string(nil), endpoints...)
	sort.Strings(canonical)
	encoded, _ := json.Marshal(canonical)
	p.identity = "overlay-pool-v1\n" + string(encoded)
	return p, nil
}

func (p *asyncDNSEndpointPool) candidates(now time.Time) ([]asyncDNSEndpointCandidate, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := p.next
	p.next = (p.next + 1) % len(p.states)
	candidates := make([]asyncDNSEndpointCandidate, 0, min(asyncDNSPoolMaxAttempts, len(p.states)))
	cooling := make([]*asyncDNSEndpointState, 0, len(p.states))
	for offset := range len(p.states) {
		state := &p.states[(start+offset)%len(p.states)]
		if now.Before(state.cooldownUntil) {
			cooling = append(cooling, state)
			continue
		}
		if len(candidates) < asyncDNSPoolMaxAttempts {
			candidates = append(candidates, asyncDNSEndpointCandidate{state.endpoint, state.failures > 0})
		}
	}
	// Passive cooldown is a preference, not permission to remove redundancy.
	// Keep ordinary >=2 eligible selection untouched. If fewer remain, reserve
	// only enough least-failed cooled peers for the existing bounded hedge.
	needed := max(0, min(2, len(p.states))-len(candidates))
	if needed > 0 {
		sort.SliceStable(cooling, func(i, j int) bool {
			if cooling[i].failures != cooling[j].failures {
				return cooling[i].failures < cooling[j].failures
			}
			return cooling[i].cooldownUntil.Before(cooling[j].cooldownUntil)
		})
		for _, state := range cooling[:needed] {
			candidates = append(candidates, asyncDNSEndpointCandidate{state.endpoint, true})
		}
	}
	// Only omitted cooled members are skips; a reserved fallback can actually
	// start and retains its real timeout/success/cancellation counters.
	for _, state := range cooling[needed:] {
		state.metrics.cooldownSkips.Add(1)
	}
	return candidates, len(cooling) - needed
}

func (p *asyncDNSEndpointPool) record(endpoint string, failed bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.states {
		state := &p.states[i]
		if state.endpoint != endpoint {
			continue
		}
		if !failed {
			state.failures = 0
			state.cooldownUntil = time.Time{}
			return
		}
		state.failures = min(state.failures+1, 6)
		state.cooldownUntil = now.Add(min(250*time.Millisecond*time.Duration(1<<(state.failures-1)), 5*time.Second))
		return
	}
}

func (p *asyncDNSEndpointPool) inherit(previous *asyncDNSEndpointPool) {
	if p == nil || previous == nil || p == previous || p.identity != previous.identity {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous.mu.Lock()
	defer previous.mu.Unlock()
	for i := range p.states {
		for _, old := range previous.states {
			if p.states[i].endpoint == old.endpoint {
				p.states[i].failures, p.states[i].cooldownUntil = old.failures, old.cooldownUntil
			}
		}
	}
}

func asyncDNSPoolRetryable(err error) bool {
	var failure *asyncDNSFetchError
	if !stderrors.As(err, &failure) {
		return false
	}
	return failure.kind == asyncDNSFailureTransport || failure.kind == asyncDNSFailureHTTP && (failure.statusCode == 502 || failure.statusCode == 503 || failure.statusCode == 504)
}

var (
	asyncDNSPoolWinnerCancel   = stderrors.New("async DNS pool winner selected")
	asyncDNSPoolTerminalCancel = stderrors.New("async DNS pool terminal response selected")
)

const asyncDNSPoolHedgeDelay = 50 * time.Millisecond

type asyncDNSPoolResult struct {
	endpoint string
	response *asyncDNSClassifierResponse
	err      error
	cause    error
	elapsed  time.Duration
}

func (m *AsyncDNSRouteMatcher) fetchPool(parent context.Context, domain string) (*asyncDNSClassifierResponse, error) {
	// A job has one configured deadline, independent of route waiters.
	deadlineCtx, deadlineCancel := context.WithTimeout(parent, m.requestTimeout)
	defer deadlineCancel()
	ctx, cancel := context.WithCancelCause(deadlineCtx)
	defer cancel(nil)
	candidates, skipped := m.pool.candidates(time.Now())
	m.stats.poolCooldownSkips.Add(uint64(skipped))
	if len(candidates) == 0 {
		m.stats.poolSyntheticCooldown.Add(1)
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: errors.New("async DNS endpoint pool is cooling down")}
	}
	// Only the coordinator launches, observes and records attempts. A result
	// slot per concurrent request lets cancellation drain without blocked sends.
	results := make(chan asyncDNSPoolResult, 2)
	active, next, attempts := 0, 0, 0
	timer := time.NewTimer(asyncDNSPoolHedgeDelay)
	defer timer.Stop()
	var hedge <-chan time.Time
	launch := func() bool {
		for next < len(candidates) && active < 2 && ctx.Err() == nil {
			i := next
			candidate := candidates[i]
			next++
			attemptCtx, attemptCancel := ctx, func() {}
			if candidate.knownFailed {
				for _, successor := range candidates[i+1:] {
					if successor.knownFailed {
						continue
					}
					deadline, _ := ctx.Deadline()
					budget := min(asyncDNSPoolHedgeDelay, time.Until(deadline)/2)
					if budget < time.Millisecond {
						attemptCtx = nil
					} else {
						attemptCtx, attemptCancel = context.WithTimeout(ctx, budget)
					}
					break
				}
			}
			if attemptCtx == nil {
				continue
			}
			if attempts > 0 {
				m.stats.poolFailovers.Add(1)
			}
			m.pool.startAttempt(candidate.endpoint, active > 0)
			attempts++
			active++
			m.stats.poolAttempts.Add(1)
			go func(endpoint string, attemptCtx context.Context, attemptCancel context.CancelFunc) {
				started := time.Now()
				response, err := m.fetchEndpoint(attemptCtx, endpoint, domain)
				cause := context.Cause(attemptCtx)
				// net/http returns a custom cancellation cause rather than the
				// context.Canceled sentinel. Normalize only this exact cause;
				// concurrent real HTTP/timeout failures remain real failures.
				if attemptCtx.Err() == context.Canceled && (stderrors.Is(err, context.Canceled) || cause != nil && stderrors.Is(err, cause)) {
					err = &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: context.Canceled}
				}
				attemptCancel()
				results <- asyncDNSPoolResult{endpoint, response, err, cause, time.Since(started)}
			}(candidate.endpoint, attemptCtx, attemptCancel)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(asyncDNSPoolHedgeDelay)
			hedge = timer.C
			return true
		}
		return false
	}
	observe := func(r asyncDNSPoolResult) {
		m.pool.observeCause(r.endpoint, r.response, r.err, r.elapsed, r.cause)
		if r.err == nil {
			m.pool.record(r.endpoint, false, time.Now())
		} else if asyncDNSPoolRetryable(r.err) && !stderrors.Is(r.err, context.Canceled) {
			m.pool.record(r.endpoint, true, time.Now())
		}
	}
	finish := func(response *asyncDNSClassifierResponse, err, cause error) (*asyncDNSClassifierResponse, error) {
		cancel(cause)
		// Context-aware HTTP requests close response bodies in fetchEndpoint.
		// No attempt goroutine is detached from its job or left behind on return.
		for active > 0 {
			r := <-results
			active--
			observe(r)
		}
		return response, err
	}
	launch()
	var lastErr error
	for active > 0 {
		select {
		case r := <-results:
			active--
			observe(r)
			if r.err == nil {
				return finish(r.response, nil, asyncDNSPoolWinnerCancel)
			}
			lastErr = r.err
			if !asyncDNSPoolRetryable(r.err) {
				return finish(nil, r.err, asyncDNSPoolTerminalCancel)
			}
			if ctx.Err() == nil {
				launch()
			}
		case <-hedge:
			hedge = nil
			launch() // Full slots never cancel a live request to make room.
		case <-ctx.Done():
			return finish(nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: ctx.Err()}, context.Cause(ctx))
		}
	}
	if lastErr == nil {
		lastErr = &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: ctx.Err()}
	}
	return nil, lastErr
}

func (m *AsyncDNSRouteMatcher) authorizeAsyncDNSURL(u *url.URL) bool {
	if u.User != nil {
		return false
	}
	if m.pool != nil {
		_, pinned := m.pool.allowed[u.String()]
		return pinned
	}
	return u.Scheme == "https" || u.String() == m.overlayEndpoint
}
