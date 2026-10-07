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
	skipped := 0
	for offset := range len(p.states) {
		state := &p.states[(start+offset)%len(p.states)]
		if now.Before(state.cooldownUntil) {
			skipped++
			state.metrics.cooldownSkips.Add(1)
			continue
		}
		if len(candidates) < asyncDNSPoolMaxAttempts {
			candidates = append(candidates, asyncDNSEndpointCandidate{state.endpoint, state.failures > 0})
		}
	}
	return candidates, skipped
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

func (m *AsyncDNSRouteMatcher) fetchPool(ctx context.Context, domain string) (*asyncDNSClassifierResponse, error) {
	// HTTP timeout is one shared operation budget, not multiplied by endpoints.
	// This context belongs to the shared job, not to a 25ms route waiter.
	ctx, cancel := context.WithTimeout(ctx, m.requestTimeout)
	defer cancel()
	candidates, skipped := m.pool.candidates(time.Now())
	m.stats.poolCooldownSkips.Add(uint64(skipped))
	if len(candidates) == 0 {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: errors.New("async DNS endpoint pool is cooling down")}
	}
	// Never-failed members keep the full remaining deadline. An expired,
	// known-failed probe reserves time for an available unpenalized successor.
	var lastErr error
	attempts := 0
	for i, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: err}
		}
		attemptCtx, attemptCancel := ctx, func() {}
		if candidate.knownFailed {
			for _, successor := range candidates[i+1:] {
				if successor.knownFailed {
					continue
				}
				deadline, _ := ctx.Deadline() // WithTimeout above always supplies it.
				budget := min(50*time.Millisecond, time.Until(deadline)/2)
				if budget < time.Millisecond {
					attemptCtx = nil // Do not spend a sub-millisecond probe budget.
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
		attempts++
		m.stats.poolAttempts.Add(1)
		started := time.Now()
		response, err := m.fetchEndpoint(attemptCtx, candidate.endpoint, domain)
		attemptCancel()
		m.pool.observe(candidate.endpoint, response, err, time.Since(started))
		if err == nil {
			m.pool.record(candidate.endpoint, false, time.Now())
			return response, nil // Pending/stale/expired/invalid shape never fan out.
		}
		lastErr = err
		retryable := asyncDNSPoolRetryable(err)
		// Deadline exhaustion still demotes a failed backend. Explicit caller
		// cancellation is not evidence that the backend is unhealthy.
		if retryable && ctx.Err() != context.Canceled {
			m.pool.record(candidate.endpoint, true, time.Now())
		}
		if !retryable || ctx.Err() != nil {
			return nil, err // Auth, overload, redirects and invalid payloads stop here.
		}
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
