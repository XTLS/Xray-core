package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/routing"
)

const (
	defaultAsyncDNSRequestTimeout = 200 * time.Millisecond
	defaultAsyncDNSCacheCapacity  = 10_000
	defaultAsyncDNSQueueCapacity  = 1_024
	defaultAsyncDNSWorkers        = 2
	defaultAsyncDNSMaxTTL         = 10 * time.Minute
	defaultAsyncDNSRetry          = time.Second
	asyncDNSSchedulerInterval     = 25 * time.Millisecond
	asyncDNSRetryBudget           = 30 * time.Second
	asyncDNSMaxAttempts           = 8
	asyncDNSActiveWindow          = time.Minute
)

var asyncDNSMatcherSequence atomic.Uint64

type asyncDNSCacheEntry struct {
	routeRU         bool
	freshUntil      time.Time
	hardUntil       time.Time
	serverHardUntil time.Time
	generation      string
	refreshAt       time.Time
	lastUsed        time.Time
}

type asyncDNSJob struct {
	next      time.Time
	deadline  time.Time
	attempts  int
	queued    bool
	exhausted bool
}

type asyncDNSClassifierRequest struct {
	Domain     string `json:"domain"`
	AllowStale bool   `json:"allowStale,omitempty"`
}

type asyncDNSClassifierResponse struct {
	State            string `json:"state"`
	Route            string `json:"route"`
	TTLMillis        uint32 `json:"ttlMillis"`
	StaleTTLMillis   uint32 `json:"staleTtlMillis"`
	Generation       string `json:"generation"`
	RetryAfterMillis uint32 `json:"retryAfterMillis"`
}

// AsyncDNSRouteMatcher maintains a bounded L1 projection of the shared L2
// classifier cache. Apply is deliberately non-blocking: a miss only queues a
// background request and returns false so the normal fallback rule wins.
type AsyncDNSRouteMatcher struct {
	endpoint        string
	bearerToken     string
	overlayEndpoint string
	client          *http.Client
	cacheCapacity   int
	maxTTL          time.Duration
	staleGrace      time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	queue           chan string
	stop            chan struct{}
	workers         sync.WaitGroup
	closed          atomic.Bool
	closeOnce       sync.Once
	matcherID       uint64

	mu    sync.Mutex
	cache map[string]asyncDNSCacheEntry
	jobs  map[string]*asyncDNSJob
	stats asyncDNSStats
}

type asyncDNSStats struct {
	freshHits        atomic.Uint64
	staleHits        atomic.Uint64
	misses           atomic.Uint64
	queueDrops       atomic.Uint64
	requests         atomic.Uint64
	errors           atomic.Uint64
	successes        atomic.Uint64
	freshResponses   atomic.Uint64
	staleResponses   atomic.Uint64
	pendingResponses atomic.Uint64
	expiredResponses atomic.Uint64
	timeoutErrors    atomic.Uint64
	canceledErrors   atomic.Uint64
	transportErrors  atomic.Uint64
	httpErrors       atomic.Uint64
	invalidResponses atomic.Uint64
	requestErrors    atomic.Uint64
	exhausted        atomic.Uint64
	evictions        atomic.Uint64
	inheritedEntries atomic.Uint64
	inheritedJobs    atomic.Uint64
}

// AsyncDNSRouteStats is a low-cardinality snapshot without domain labels.
type AsyncDNSRouteStats struct {
	FreshHits, StaleHits, Misses, QueueDrops, Requests, Errors, Exhausted                       uint64
	Successes, FreshResponses, StaleResponses, PendingResponses, ExpiredResponses               uint64
	TimeoutErrors, CanceledErrors, TransportErrors, HTTPErrors, InvalidResponses, RequestErrors uint64
	MatcherID, Evictions, InheritedEntries, InheritedJobs                                       uint64
	Entries, Jobs, Queued                                                                       int
}

func (m *AsyncDNSRouteMatcher) Stats() AsyncDNSRouteStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return AsyncDNSRouteStats{
		FreshHits: m.stats.freshHits.Load(), StaleHits: m.stats.staleHits.Load(),
		Misses: m.stats.misses.Load(), QueueDrops: m.stats.queueDrops.Load(),
		Requests: m.stats.requests.Load(), Errors: m.stats.errors.Load(), Exhausted: m.stats.exhausted.Load(),
		Successes: m.stats.successes.Load(), FreshResponses: m.stats.freshResponses.Load(),
		StaleResponses: m.stats.staleResponses.Load(), PendingResponses: m.stats.pendingResponses.Load(), ExpiredResponses: m.stats.expiredResponses.Load(),
		TimeoutErrors: m.stats.timeoutErrors.Load(), CanceledErrors: m.stats.canceledErrors.Load(),
		TransportErrors: m.stats.transportErrors.Load(), HTTPErrors: m.stats.httpErrors.Load(),
		InvalidResponses: m.stats.invalidResponses.Load(), RequestErrors: m.stats.requestErrors.Load(),
		MatcherID: m.matcherID, Evictions: m.stats.evictions.Load(), InheritedEntries: m.stats.inheritedEntries.Load(), InheritedJobs: m.stats.inheritedJobs.Load(),
		Entries: len(m.cache), Jobs: len(m.jobs), Queued: len(m.queue),
	}
}

func NewAsyncDNSRouteMatcher(config *AsyncDnsRouteConfig) (*AsyncDNSRouteMatcher, error) {
	if config == nil {
		return nil, errors.New("async DNS route config is nil")
	}

	endpoint, err := url.ParseRequestURI(config.GetEndpoint())
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return nil, errors.New("async DNS route endpoint must be an absolute HTTP(S) URL")
	}
	bearerToken, err := readAsyncDNSBearerToken()
	if err != nil {
		return nil, err
	}
	overlayEndpoint := os.Getenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT")
	if overlayEndpoint != "" {
		overlay, parseErr := url.Parse(overlayEndpoint)
		if parseErr != nil || overlay.Scheme != "http" || overlay.User != nil || overlay.RawQuery != "" || overlay.ForceQuery || overlay.Fragment != "" || net.ParseIP(overlay.Hostname()) == nil || overlay.Port() == "" || bearerToken == "" {
			return nil, errors.New("async DNS overlay requires an exact HTTP IP endpoint with explicit port and bearer token")
		}
	}
	if bearerToken != "" && (endpoint.User != nil || (endpoint.Scheme != "https" && endpoint.String() != overlayEndpoint)) {
		return nil, errors.New("authenticated async DNS route endpoint requires HTTPS without URL credentials")
	}

	requestTimeout := durationOrDefault(config.GetRequestTimeoutMillis(), defaultAsyncDNSRequestTimeout)
	cacheCapacity := int(config.GetCacheCapacity())
	if cacheCapacity == 0 {
		cacheCapacity = defaultAsyncDNSCacheCapacity
	}
	queueCapacity := int(config.GetQueueCapacity())
	if queueCapacity == 0 {
		queueCapacity = defaultAsyncDNSQueueCapacity
	}
	workerCount := int(config.GetWorkers())
	if workerCount == 0 {
		workerCount = defaultAsyncDNSWorkers
	}
	minTTL := durationOrDefault(config.GetMinTtlMillis(), time.Millisecond)
	maxTTL := durationOrDefault(config.GetMaxTtlMillis(), defaultAsyncDNSMaxTTL)
	if minTTL > maxTTL {
		return nil, errors.New("async DNS route min TTL is greater than max TTL")
	}
	staleGrace := time.Duration(config.GetStaleGraceMillis()) * time.Millisecond
	if staleGrace > time.Hour {
		return nil, errors.New("async DNS route stale grace exceeds one hour")
	}
	ctx, cancel := context.WithCancel(context.Background())

	m := &AsyncDNSRouteMatcher{
		endpoint:        endpoint.String(),
		bearerToken:     bearerToken,
		overlayEndpoint: overlayEndpoint,
		client: &http.Client{
			Timeout: requestTimeout,
			// Never forward service credentials to a redirect destination.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cacheCapacity: cacheCapacity,
		maxTTL:        maxTTL,
		staleGrace:    staleGrace,
		ctx:           ctx,
		cancel:        cancel,
		queue:         make(chan string, queueCapacity),
		stop:          make(chan struct{}),
		cache:         make(map[string]asyncDNSCacheEntry, cacheCapacity),
		jobs:          make(map[string]*asyncDNSJob),
		matcherID:     asyncDNSMatcherSequence.Add(1),
	}
	if endpoint.String() == overlayEndpoint {
		// The explicit endpoint is operator-attested encrypted overlay transport.
		// Never send its credential through HTTP_PROXY or a DNS-resolved host.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		m.client.Transport = transport
	}
	m.workers.Add(workerCount)
	for range workerCount {
		go m.runWorker()
	}
	m.workers.Add(1)
	go m.runScheduler()
	return m, nil
}

// inheritState is called only for an identical full router configuration. The
// new matcher owns its own workers/HTTP context; only bounded value state moves.
// Absolute deadlines, generations, retry attempts and cooldowns never restart.
func (m *AsyncDNSRouteMatcher) inheritState(previous *AsyncDNSRouteMatcher) {
	if m == previous || m.bearerToken != previous.bearerToken {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous.mu.Lock()
	defer previous.mu.Unlock()
	if previous.closed.Load() {
		return
	}
	now := time.Now()
	for domain, entry := range previous.cache {
		if len(m.cache) >= m.cacheCapacity {
			break
		}
		if now.Before(entry.serverHardUntil) {
			m.cache[domain] = entry
		}
	}
	for domain, previousJob := range previous.jobs {
		if len(m.jobs) >= m.cacheCapacity {
			break
		}
		job := *previousJob
		if job.exhausted && !now.Before(job.next) {
			continue
		}
		if !job.exhausted && !now.Before(job.deadline) {
			continue
		}
		if job.queued {
			// An old in-flight request will be cancelled when old rules close.
			// Resume through the bounded scheduler, not by copying HTTP state.
			job.queued = false
			job.next = now
		}
		m.jobs[domain] = &job
	}
	m.stats.inheritedEntries.Store(uint64(len(m.cache)))
	m.stats.inheritedJobs.Store(uint64(len(m.jobs)))
}

// The secret is local process configuration, never part of the owner-delivered
// routing payload. It is read once during matcher construction (restart/reload
// after rotation), outside the non-blocking Apply path. An explicitly configured
// but invalid secret rejects the new matcher instead of falling back anonymously.
func readAsyncDNSBearerToken() (string, error) {
	path := os.Getenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE")
	if path == "" {
		return "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot read async DNS bearer token file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("async DNS bearer token file must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("cannot read async DNS bearer token file or token exceeds 4096 bytes")
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.IndexFunc(token, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/=", r))
	}) >= 0 {
		return "", errors.New("async DNS bearer token file contains an empty or invalid token")
	}
	return token, nil
}

func durationOrDefault(millis uint32, fallback time.Duration) time.Duration {
	if millis == 0 {
		return fallback
	}
	return time.Duration(millis) * time.Millisecond
}

// Apply consults only bounded in-memory state. Stale RU is accepted only within
// the explicit local grace and the classifier's authoritative hard deadline.
func (m *AsyncDNSRouteMatcher) Apply(ctx routing.Context) bool {
	domain := normalizeAsyncDNSDomain(ctx.GetTargetDomain())
	if domain == "" || len(domain) > 253 || m.closed.Load() {
		return false
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, found := m.cache[domain]; found {
		if now.Before(entry.hardUntil) {
			entry.lastUsed = now
			m.cache[domain] = entry
			if !now.Before(entry.refreshAt) {
				m.startJob(domain, now)
			}
			if now.Before(entry.freshUntil) {
				m.stats.freshHits.Add(1)
			} else {
				m.stats.staleHits.Add(1)
			}
			return entry.routeRU
		}
		// Keep a bounded tombstone until the server's generation expires. A
		// reread must not resurrect grace after our shorter local hard limit.
		if !now.Before(entry.serverHardUntil) {
			delete(m.cache, domain)
		}
	}
	m.stats.misses.Add(1)
	m.startJob(domain, now)
	return false
}

// Caller holds mu. Queue overflow leaves a bounded scheduled job, never a
// per-domain goroutine or an unbounded negative/retry cache.
func (m *AsyncDNSRouteMatcher) startJob(domain string, now time.Time) {
	if m.closed.Load() || m.jobs[domain] != nil {
		return
	}
	if len(m.jobs) >= m.cacheCapacity {
		m.stats.queueDrops.Add(1)
		return
	}
	job := &asyncDNSJob{next: now, deadline: now.Add(asyncDNSRetryBudget)}
	m.jobs[domain] = job
	m.queueJob(domain, job, now)
}

func (m *AsyncDNSRouteMatcher) queueJob(domain string, job *asyncDNSJob, now time.Time) {
	select {
	case m.queue <- domain:
		job.queued = true
		job.attempts++
	default:
		job.next = now.Add(asyncDNSSchedulerInterval)
		m.stats.queueDrops.Add(1)
	}
}

func normalizeAsyncDNSDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func (m *AsyncDNSRouteMatcher) runWorker() {
	defer m.workers.Done()
	for {
		select {
		case <-m.stop:
			return
		case domain := <-m.queue:
			if m.closed.Load() {
				return
			}
			m.refresh(domain)
		}
	}
}

func (m *AsyncDNSRouteMatcher) runScheduler() {
	defer m.workers.Done()
	ticker := time.NewTicker(asyncDNSSchedulerInterval)
	defer ticker.Stop()
	nextStats := time.Now().Add(time.Minute)
	for {
		select {
		case <-m.stop:
			return
		case now := <-ticker.C:
			m.mu.Lock()
			for domain, job := range m.jobs {
				if job.queued || now.Before(job.next) {
					continue
				}
				if job.exhausted {
					delete(m.jobs, domain)
					continue
				}
				if !now.Before(job.deadline) || job.attempts >= asyncDNSMaxAttempts {
					m.exhaustJob(job, now)
					continue
				}
				m.queueJob(domain, job, now)
			}
			for domain, entry := range m.cache {
				if !now.Before(entry.serverHardUntil) {
					delete(m.cache, domain)
					continue
				}
				if !now.Before(entry.hardUntil) {
					continue
				}
				if !now.Before(entry.refreshAt) && now.Sub(entry.lastUsed) < asyncDNSActiveWindow {
					m.startJob(domain, now)
				}
			}
			m.mu.Unlock()
			if !now.Before(nextStats) {
				s := m.Stats()
				errors.LogInfo(m.ctx, "async DNS route stats matcherID=", s.MatcherID,
					" entries=", s.Entries, " jobs=", s.Jobs, " queued=", s.Queued,
					" capacity=", m.cacheCapacity, " queueCapacity=", cap(m.queue), " graceMillis=", m.staleGrace.Milliseconds(),
					" freshHits=", s.FreshHits, " staleHits=", s.StaleHits, " misses=", s.Misses,
					" requests=", s.Requests, " errors=", s.Errors, " evictions=", s.Evictions,
					" successes=", s.Successes, " freshResponses=", s.FreshResponses, " staleResponses=", s.StaleResponses,
					" pendingResponses=", s.PendingResponses, " expiredResponses=", s.ExpiredResponses,
					" timeoutErrors=", s.TimeoutErrors, " canceledErrors=", s.CanceledErrors, " transportErrors=", s.TransportErrors,
					" httpErrors=", s.HTTPErrors, " invalidResponses=", s.InvalidResponses, " requestErrors=", s.RequestErrors,
					" queueDrops=", s.QueueDrops, " exhausted=", s.Exhausted,
					" inheritedEntries=", s.InheritedEntries, " inheritedJobs=", s.InheritedJobs)
				nextStats = now.Add(time.Minute)
			}
		}
	}
}

func (m *AsyncDNSRouteMatcher) exhaustJob(job *asyncDNSJob, now time.Time) {
	job.exhausted = true
	job.next = now.Add(asyncDNSRetryBudget)
	m.stats.exhausted.Add(1)
}

func (m *AsyncDNSRouteMatcher) refresh(domain string) {
	started := time.Now()
	m.mu.Lock()
	job := m.jobs[domain]
	if job == nil || m.closed.Load() {
		m.mu.Unlock()
		return
	}
	if !started.Before(job.deadline) {
		job.queued = false
		m.exhaustJob(job, started)
		m.mu.Unlock()
		return
	}
	deadline := job.deadline
	m.mu.Unlock()
	ctx, cancel := context.WithDeadline(m.ctx, deadline)
	defer cancel()
	m.stats.requests.Add(1)
	response, err := m.fetchContext(ctx, domain)
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	job = m.jobs[domain]
	if job == nil || m.closed.Load() {
		return
	}
	job.queued = false
	if err != nil {
		m.recordFetchError(err)
	} else {
		outcome := classifyAsyncDNSResponse(response, now.Sub(started))
		m.recordResponse(outcome)
		if outcome != asyncDNSResponseInvalid && m.acceptResponse(domain, response, started, now) {
			delete(m.jobs, domain)
			return
		}
	}
	if job.attempts >= asyncDNSMaxAttempts || !now.Before(job.deadline) {
		m.exhaustJob(job, now)
		return
	}
	delay := 250 * time.Millisecond * time.Duration(1<<min(job.attempts-1, 5))
	if response != nil && response.RetryAfterMillis > 0 {
		delay = max(delay, time.Duration(response.RetryAfterMillis)*time.Millisecond)
	}
	delay = min(delay, 5*time.Second)
	delay += time.Duration(rand.Int64N(int64(delay/5) + 1))
	job.next = minTime(now.Add(delay), job.deadline)
	if entry, ok := m.cache[domain]; ok {
		entry.refreshAt = job.next
		m.cache[domain] = entry
	}
}

// A fresh classification supersedes last-good immediately, including RU->other.
// Stale is only a retained projection: it never extends an existing hard deadline.
func (m *AsyncDNSRouteMatcher) acceptResponse(domain string, response *asyncDNSClassifierResponse, started, now time.Time) bool {
	elapsed := now.Sub(started)
	outcome := classifyAsyncDNSResponse(response, elapsed)
	if outcome == asyncDNSResponseInvalid || outcome == asyncDNSResponsePending {
		return false
	}
	fresh := time.Duration(response.TTLMillis)*time.Millisecond - elapsed
	hard := time.Duration(response.StaleTTLMillis)*time.Millisecond - elapsed
	entry := asyncDNSCacheEntry{routeRU: response.Route == "ru", lastUsed: now, generation: response.Generation}
	if previous, ok := m.cache[domain]; ok {
		entry.lastUsed = previous.lastUsed
	}
	switch outcome {
	case asyncDNSResponseFresh:
		entry.serverHardUntil = now.Add(fresh)
		if response.StaleTTLMillis > 0 {
			entry.serverHardUntil = now.Add(hard)
		}
		fresh = min(fresh, m.maxTTL)
		entry.freshUntil = now.Add(fresh)
		entry.hardUntil = entry.freshUntil
		if m.staleGrace > 0 && response.StaleTTLMillis > 0 {
			entry.hardUntil = now.Add(min(hard, fresh+m.staleGrace))
		}
		if previous, ok := m.cache[domain]; ok && (entry.generation == "" || previous.generation == "" || entry.generation == previous.generation) {
			// Only a proven new DNS fill renews a local retention window. L2
			// cache rereads cannot mint grace, even if local maxTTL is shorter.
			entry.hardUntil = minTime(entry.hardUntil, previous.hardUntil)
			entry.serverHardUntil = minTime(entry.serverHardUntil, previous.serverHardUntil)
			// Reading the same L2 generation does not refill it. Repeating an
			// 80%-of-remaining prefetch here causes a cascade near expiration.
			entry.refreshAt = entry.freshUntil
		}
		// A valid fresh read remains usable; the clamp limits stale allowance,
		// not newly proven freshness. This also preserves legacy fresh-only L1.
		if entry.hardUntil.Before(entry.freshUntil) {
			entry.hardUntil = entry.freshUntil
		}
		if entry.refreshAt.IsZero() {
			entry.refreshAt = now.Add(fresh * 4 / 5)
		}
	case asyncDNSResponseStale, asyncDNSResponseExpired:
		if m.staleGrace == 0 || response.StaleTTLMillis == 0 || hard <= 0 {
			return false
		}
		entry.freshUntil = now
		grace := m.staleGrace
		if outcome == asyncDNSResponseExpired {
			// Grace begins at the original fresh deadline, not at receipt.
			// Network delay must never grant extra stale lifetime.
			grace += fresh
		}
		entry.hardUntil = now.Add(min(hard, grace))
		entry.serverHardUntil = now.Add(hard)
		if previous, ok := m.cache[domain]; ok {
			entry.hardUntil = minTime(entry.hardUntil, previous.hardUntil)
			entry.serverHardUntil = minTime(entry.serverHardUntil, previous.serverHardUntil)
			// A stale reply cannot downgrade a still-fresh local result.
			if now.Before(previous.freshUntil) {
				return false
			}
		}
		if !now.Before(entry.hardUntil) {
			return false
		}
		entry.refreshAt = now.Add(defaultAsyncDNSRetry)
	default:
		return false
	}
	if _, found := m.cache[domain]; !found {
		m.evictIfNeeded(now)
	}
	m.cache[domain] = entry
	return outcome == asyncDNSResponseFresh
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (m *AsyncDNSRouteMatcher) evictIfNeeded(now time.Time) {
	if len(m.cache) < m.cacheCapacity {
		return
	}
	for domain, entry := range m.cache {
		if !now.Before(entry.hardUntil) {
			delete(m.cache, domain)
			return
		}
	}
	for domain := range m.cache {
		delete(m.cache, domain)
		m.stats.evictions.Add(1)
		return
	}
}

func (m *AsyncDNSRouteMatcher) fetch(domain string) (*asyncDNSClassifierResponse, error) {
	return m.fetchContext(m.ctx, domain)
}

func (m *AsyncDNSRouteMatcher) fetchContext(ctx context.Context, domain string) (*asyncDNSClassifierResponse, error) {
	body, err := json.Marshal(asyncDNSClassifierRequest{Domain: domain, AllowStale: m.staleGrace > 0})
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if m.bearerToken != "" {
		if req.URL.User != nil || (req.URL.Scheme != "https" && req.URL.String() != m.overlayEndpoint) {
			return nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest, err: errors.New("refusing async DNS bearer token over an insecure endpoint")}
		}
		req.Header.Set("Authorization", "Bearer "+m.bearerToken)
	}
	response, err := m.client.Do(req)
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureHTTP, err: errors.New("async DNS route classifier returned status ", response.StatusCode)}
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, 32*1024+1))
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: err}
	}
	if len(data) > 32*1024 {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureInvalidResponse, err: errors.New("async DNS classifier response exceeds 32 KiB")}
	}
	decoded := new(asyncDNSClassifierResponse)
	if err := json.Unmarshal(data, decoded); err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureInvalidResponse, err: err}
	}
	return decoded, nil
}

func (m *AsyncDNSRouteMatcher) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		m.cancel()
		close(m.stop)
		m.workers.Wait()
		m.client.CloseIdleConnections()
		m.mu.Lock()
		clear(m.cache)
		clear(m.jobs)
		m.mu.Unlock()
	})
	return nil
}
