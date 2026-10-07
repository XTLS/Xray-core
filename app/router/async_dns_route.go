package router

import (
	"bytes"
	"container/list"
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
	// Closed after the first RPC outcome, including pending/error. Waiters never
	// wait for the retry loop, and their lifetime does not own the shared job.
	firstDone     chan struct{}
	firstFinished bool
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
// classifier cache. Misses may opt in to a bounded wait for the existing shared
// worker's first response. A zero budget keeps the legacy non-blocking behavior.
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
	routeWait       time.Duration
	maxWaiters      int
	waiters         int
	lru             list.List
	lruIndex        map[string]*list.Element
	expired         list.List
	expiredIndex    map[string]*list.Element
	cleanupCursor   *list.Element
	snapshot        *asyncDNSSnapshotStore
	dirty           uint64
	failureStreak   uint32
	retryAfter      time.Time

	pool              *asyncDNSEndpointPool
	transportIdentity string
	requestTimeout    time.Duration

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
	waitStarts       atomic.Uint64
	waitDrops        atomic.Uint64
	waitTimeouts     atomic.Uint64
	expirations      atomic.Uint64
	snapshotWrites   atomic.Uint64
	snapshotErrors   atomic.Uint64
	restoredEntries  atomic.Uint64

	poolAttempts          atomic.Uint64
	poolFailovers         atomic.Uint64
	poolCooldownSkips     atomic.Uint64
	poolSyntheticCooldown atomic.Uint64
}

// AsyncDNSRouteStats is a low-cardinality snapshot without domain labels.
type AsyncDNSRouteStats struct {
	FreshHits, StaleHits, Misses, QueueDrops, Requests, Errors, Exhausted                             uint64
	Successes, FreshResponses, StaleResponses, PendingResponses, ExpiredResponses                     uint64
	TimeoutErrors, CanceledErrors, TransportErrors, HTTPErrors, InvalidResponses, RequestErrors       uint64
	MatcherID, Evictions, InheritedEntries, InheritedJobs                                             uint64
	Entries, Jobs, Queued                                                                             int
	WaitStarts, WaitDrops, WaitTimeouts, Expirations, SnapshotWrites, SnapshotErrors, RestoredEntries uint64
	Waiters                                                                                           int
	PoolAttempts, PoolFailovers, PoolCooldownSkips                                                    uint64
	PoolSyntheticCooldown                                                                             uint64
	PoolSize                                                                                          int
}

func (m *AsyncDNSRouteMatcher) Stats() AsyncDNSRouteStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	poolSize := 0
	if m.pool != nil {
		poolSize = len(m.pool.states)
	}
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
		WaitStarts: m.stats.waitStarts.Load(), WaitDrops: m.stats.waitDrops.Load(), WaitTimeouts: m.stats.waitTimeouts.Load(), Waiters: m.waiters,
		Expirations: m.stats.expirations.Load(), SnapshotWrites: m.stats.snapshotWrites.Load(), SnapshotErrors: m.stats.snapshotErrors.Load(), RestoredEntries: m.stats.restoredEntries.Load(),
		PoolAttempts: m.stats.poolAttempts.Load(), PoolFailovers: m.stats.poolFailovers.Load(), PoolCooldownSkips: m.stats.poolCooldownSkips.Load(), PoolSize: poolSize, PoolSyntheticCooldown: m.stats.poolSyntheticCooldown.Load(),
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
	pool, err := readAsyncDNSOverlayPool(overlayEndpoint, bearerToken)
	if err != nil {
		return nil, err
	}
	identity := endpoint.String()
	if endpoint.String() != overlayEndpoint {
		pool = nil // A transport pool never captures unrelated owner rules.
	} else if pool != nil {
		identity = pool.identity
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
	if config.GetRouteWaitMillis() > 100 || config.GetMaxWaiters() > 4096 {
		return nil, errors.New("async DNS route wait exceeds 100ms or waiter limit exceeds 4096")
	}
	if cacheCapacity > 100000 || queueCapacity > 100000 || workerCount > 64 {
		return nil, errors.New("async DNS route capacity exceeds bounded limits")
	}
	store, err := newAsyncDNSSnapshotStore(config, identity, maxTTL, staleGrace)
	if err != nil {
		return nil, err
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
		routeWait:     time.Duration(config.GetRouteWaitMillis()) * time.Millisecond,
		maxWaiters:    int(config.GetMaxWaiters()),
		lruIndex:      make(map[string]*list.Element, cacheCapacity),
		snapshot:      store,

		pool:              pool,
		transportIdentity: identity,
		requestTimeout:    requestTimeout,
	}
	if m.maxWaiters == 0 {
		m.maxWaiters = 256
	}
	if store != nil {
		m.restoreSnapshot()
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
	if store != nil {
		go m.runSnapshotWriter()
	}
	return m, nil
}

// inheritState is called only for an identical full router configuration. The
// new matcher owns its own workers/HTTP context; only bounded value state moves.
// Absolute deadlines, generations, retry attempts and cooldowns never restart.
func (m *AsyncDNSRouteMatcher) inheritState(previous *AsyncDNSRouteMatcher) {
	if m == previous || m.bearerToken != previous.bearerToken || m.transportIdentity != previous.transportIdentity {
		return
	}
	m.pool.inherit(previous.pool)
	m.mu.Lock()
	defer m.mu.Unlock()
	previous.mu.Lock()
	defer previous.mu.Unlock()
	if previous.closed.Load() {
		return
	}
	now := time.Now()
	// Oldest first preserves relative LRU order. Tests/legacy state may have no
	// index yet; rebuild it once at the reload boundary, never on a route miss.
	previous.ensureLRU()
	clear(m.cache)
	m.lru.Init()
	clear(m.lruIndex)
	m.cleanupCursor = nil
	m.expired.Init()
	clear(m.expiredIndex)
	for item := previous.lru.Back(); item != nil; item = item.Prev() {
		domain := item.Value.(string)
		entry := previous.cache[domain]
		if len(m.cache) >= m.cacheCapacity {
			break
		}
		if now.Before(entry.serverHardUntil) {
			m.putEntry(domain, entry)
		}
	}
	for domain, previousJob := range previous.jobs {
		if len(m.jobs) >= m.cacheCapacity {
			break
		}
		job := *previousJob
		// Channels belong to old workers, never to a replacement matcher.
		if job.firstDone != nil {
			job.firstDone = make(chan struct{})
			if job.firstFinished {
				close(job.firstDone)
			}
		}
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
	m.failureStreak = previous.failureStreak
	m.retryAfter = previous.retryAfter
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

// Apply reads L1 under its mutex; the optional wait performs no I/O and holds
// no cache lock. Freshness is rechecked after waking, so transit time never
// turns an expired response into a usable classification.
func (m *AsyncDNSRouteMatcher) Apply(ctx routing.Context) bool {
	domain := normalizeAsyncDNSDomain(ctx.GetTargetDomain())
	if domain == "" || len(domain) > 253 || m.closed.Load() {
		return false
	}
	now := time.Now()
	m.mu.Lock()
	if route, found := m.lookup(domain, now); found {
		m.mu.Unlock()
		return route
	}
	m.stats.misses.Add(1)
	m.startJob(domain, now)
	job := m.jobs[domain]
	if m.routeWait == 0 || job == nil || !job.queued || job.firstFinished || m.waiters >= m.maxWaiters {
		if m.routeWait > 0 && (m.waiters >= m.maxWaiters || (job != nil && !job.queued && !job.firstFinished)) {
			m.stats.waitDrops.Add(1)
		}
		m.mu.Unlock()
		return false
	}
	deadline, connection := asyncDNSWaitDeadline(ctx, now, m.routeWait)
	if !now.Before(deadline) || connection.Err() != nil {
		m.mu.Unlock()
		return false
	}
	m.waiters++
	m.stats.waitStarts.Add(1)
	done := job.firstDone
	m.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		m.stats.waitTimeouts.Add(1)
	case <-connection.Done():
	case <-m.stop:
	}
	m.mu.Lock()
	m.waiters--
	defer m.mu.Unlock()
	if m.closed.Load() || connection.Err() != nil || !time.Now().Before(deadline) {
		return false
	}
	route, found := m.lookup(domain, time.Now())
	return found && route
}

// lookup is called with mu held. A hit alone, including a cached non-RU result,
// records user popularity. Background refresh never promotes an existing key.
func (m *AsyncDNSRouteMatcher) lookup(domain string, now time.Time) (bool, bool) {
	if entry, found := m.cache[domain]; found {
		if now.Before(entry.hardUntil) {
			entry.lastUsed = now
			m.putEntry(domain, entry)
			m.lru.MoveToFront(m.lruIndex[domain])
			if !now.Before(entry.refreshAt) {
				m.startJob(domain, now)
			}
			if now.Before(entry.freshUntil) {
				m.stats.freshHits.Add(1)
			} else {
				m.stats.staleHits.Add(1)
			}
			return entry.routeRU, true
		}
		// Retain the generation tombstone until its authoritative deadline, unless
		// bounded capacity eviction removes it. It cannot authorize stale routing.
		if !now.Before(entry.serverHardUntil) {
			m.removeEntry(domain, true)
		} else {
			m.markExpired(domain)
		}
	}
	return false, false
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
	job := &asyncDNSJob{next: now, deadline: now.Add(asyncDNSRetryBudget), firstDone: make(chan struct{})}
	m.jobs[domain] = job
	m.queueJob(domain, job, now)
}

func (m *AsyncDNSRouteMatcher) queueJob(domain string, job *asyncDNSJob, now time.Time) {
	if now.Before(m.retryAfter) {
		job.next = m.retryAfter
		return
	}
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
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	// Match the classifier's domain-only input contract before creating a job.
	// Invalid targets keep the existing fallback; they cannot acquire L1 state.
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return ""
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return domain
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
			m.scanEntries(now, 64)
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
					" inheritedEntries=", s.InheritedEntries, " inheritedJobs=", s.InheritedJobs,
					" routeWaitMillis=", m.routeWait.Milliseconds(), " waiters=", s.Waiters, " waitStarts=", s.WaitStarts,
					" waitDrops=", s.WaitDrops, " waitTimeouts=", s.WaitTimeouts, " expirations=", s.Expirations,
					" snapshotWrites=", s.SnapshotWrites, " snapshotErrors=", s.SnapshotErrors, " restoredEntries=", s.RestoredEntries,
					" poolSize=", s.PoolSize, " poolAttempts=", s.PoolAttempts, " poolFailovers=", s.PoolFailovers, " poolCooldownSkips=", s.PoolCooldownSkips, " poolSyntheticCooldown=", s.PoolSyntheticCooldown)
				if m.pool != nil {
					samples, discarded := m.pool.failureSamples.take()
					for _, sample := range samples {
						errors.LogInfo(m.ctx, "async DNS pool failed job matcherID=", s.MatcherID, " sample=", sample)
					}
					if discarded > 0 {
						errors.LogInfo(m.ctx, "async DNS pool failed jobs discarded matcherID=", s.MatcherID, " count=", discarded)
					}
					for i, endpoint := range m.pool.endpointStats() {
						errors.LogInfo(m.ctx, endpoint.logLine(s.MatcherID, i))
						samples, discarded := m.pool.states[i].metrics.trace.takeErrorSamples()
						for _, sample := range samples {
							errors.LogInfo(m.ctx, sample.logLine(s.MatcherID, i))
						}
						if discarded > 0 {
							errors.LogInfo(m.ctx, "async DNS HTTP error samples discarded matcher=", s.MatcherID, " endpointIndex=", i, " count=", discarded)
						}
					}
				}
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
	if started.Before(m.retryAfter) {
		job.queued = false
		job.next = m.retryAfter
		finishAsyncDNSFirst(job)
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
	defer finishAsyncDNSFirst(job)
	if err != nil {
		m.recordFetchError(err)
		m.recordFailure(now)
	} else {
		outcome := classifyAsyncDNSResponse(response, now.Sub(started))
		m.recordResponse(outcome)
		if outcome == asyncDNSResponseInvalid {
			m.recordFailure(now)
		} else {
			m.failureStreak = 0
			m.retryAfter = time.Time{}
		}
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
		m.putEntry(domain, entry)
	}
}

// Shared failure cooldown also bounds RPCs for a stream of unique domains while
// the classifier is unavailable. It never disables valid in-memory decisions.
func (m *AsyncDNSRouteMatcher) recordFailure(now time.Time) {
	m.failureStreak = min(m.failureStreak+1, 8)
	if m.failureStreak >= 3 {
		m.retryAfter = now.Add(min(250*time.Millisecond*time.Duration(1<<(m.failureStreak-3)), 5*time.Second))
	}
}

func finishAsyncDNSFirst(job *asyncDNSJob) {
	if !job.firstFinished && job.firstDone != nil {
		close(job.firstDone)
		job.firstFinished = true
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
	m.putEntry(domain, entry)
	return outcome == asyncDNSResponseFresh
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Bounded expiry work precedes a single O(1) LRU victim removal. An expired
// entry missed by this small scan remains unusable (lookup checks deadlines).
func (m *AsyncDNSRouteMatcher) evictIfNeeded(now time.Time) {
	if len(m.cache) < m.cacheCapacity {
		return
	}
	m.scanEntries(now, 16)
	if len(m.cache) < m.cacheCapacity {
		return
	}
	if candidate := m.expired.Front(); candidate != nil {
		m.removeEntry(candidate.Value.(string), true)
		return
	}
	if item := m.lru.Back(); item != nil {
		m.removeEntry(item.Value.(string), false)
		m.stats.evictions.Add(1)
	}
}

func (m *AsyncDNSRouteMatcher) putEntry(domain string, entry asyncDNSCacheEntry) {
	if m.lruIndex == nil {
		m.lruIndex = make(map[string]*list.Element)
	}
	if m.lruIndex[domain] == nil {
		m.lruIndex[domain] = m.lru.PushFront(domain)
	}
	m.cache[domain] = entry
	if item := m.expiredIndex[domain]; item != nil {
		m.expired.Remove(item)
		delete(m.expiredIndex, domain)
	}
	m.dirty++
}

func (m *AsyncDNSRouteMatcher) markExpired(domain string) {
	if m.expiredIndex == nil {
		m.expiredIndex = make(map[string]*list.Element)
	}
	if m.expiredIndex[domain] == nil {
		m.expiredIndex[domain] = m.expired.PushBack(domain)
	}
}

func (m *AsyncDNSRouteMatcher) removeEntry(domain string, expired bool) {
	if item := m.expiredIndex[domain]; item != nil {
		m.expired.Remove(item)
		delete(m.expiredIndex, domain)
	}
	if item := m.lruIndex[domain]; item != nil {
		if m.cleanupCursor == item {
			m.cleanupCursor = item.Next()
		}
		m.lru.Remove(item)
		delete(m.lruIndex, domain)
	}
	if _, ok := m.cache[domain]; ok {
		delete(m.cache, domain)
		m.dirty++
		if expired {
			m.stats.expirations.Add(1)
		}
	}
}

func (m *AsyncDNSRouteMatcher) ensureLRU() {
	for domain := range m.cache {
		if m.lruIndex[domain] == nil {
			m.putEntry(domain, m.cache[domain])
		}
	}
}

func (m *AsyncDNSRouteMatcher) scanEntries(now time.Time, budget int) {
	if m.cleanupCursor == nil {
		m.cleanupCursor = m.lru.Front()
	}
	for budget > 0 && m.cleanupCursor != nil {
		item := m.cleanupCursor
		m.cleanupCursor = item.Next()
		domain := item.Value.(string)
		entry := m.cache[domain]
		if !now.Before(entry.serverHardUntil) {
			m.removeEntry(domain, true)
		} else if !now.Before(entry.hardUntil) {
			m.markExpired(domain)
		} else if m.jobs != nil && now.Before(entry.hardUntil) && !now.Before(entry.refreshAt) && now.Sub(entry.lastUsed) < asyncDNSActiveWindow {
			m.startJob(domain, now)
		}
		budget--
	}
}

func (m *AsyncDNSRouteMatcher) fetch(domain string) (*asyncDNSClassifierResponse, error) {
	return m.fetchContext(m.ctx, domain)
}

func (m *AsyncDNSRouteMatcher) fetchContext(ctx context.Context, domain string) (*asyncDNSClassifierResponse, error) {
	if m.pool != nil {
		return m.fetchPool(ctx, domain)
	}
	return m.fetchEndpoint(ctx, m.endpoint, domain)
}

func (m *AsyncDNSRouteMatcher) fetchEndpoint(ctx context.Context, endpoint, domain string) (result *asyncDNSClassifierResponse, fetchErr error) {
	trace := m.newHTTPAttemptTrace(endpoint)
	if trace != nil {
		trace.diagnostic, _ = ctx.Value(asyncDNSPoolTraceKey{}).(*asyncDNSPoolTraceSample)
	}
	defer func() { trace.finish(fetchErr) }()
	body, err := json.Marshal(asyncDNSClassifierRequest{Domain: domain, AllowStale: m.staleGrace > 0})
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if m.bearerToken != "" {
		if !m.authorizeAsyncDNSURL(req.URL) {
			return nil, &asyncDNSFetchError{kind: asyncDNSFailureRequest, err: errors.New("refusing async DNS bearer token over an insecure endpoint")}
		}
		req.Header.Set("Authorization", "Bearer "+m.bearerToken)
	}
	req = trace.request(req)
	response, err := m.client.Do(req)
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureHTTP, statusCode: response.StatusCode, err: errors.New("async DNS route classifier returned status ", response.StatusCode)}
	}

	trace.phase(asyncDNSHTTPBody)
	data, err := io.ReadAll(io.LimitReader(response.Body, 32*1024+1))
	if err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureTransport, err: err}
	}
	if len(data) > 32*1024 {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureInvalidResponse, err: errors.New("async DNS classifier response exceeds 32 KiB")}
	}
	trace.phase(asyncDNSHTTPDecode)
	decoded := new(asyncDNSClassifierResponse)
	if err := json.Unmarshal(data, decoded); err != nil {
		return nil, &asyncDNSFetchError{kind: asyncDNSFailureInvalidResponse, err: err}
	}
	trace.phase(asyncDNSHTTPComplete)
	return decoded, nil
}

func (m *AsyncDNSRouteMatcher) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		m.cancel()
		close(m.stop)
		done := make(chan struct{})
		go func() { m.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		m.closeSnapshotWriter()
		m.client.CloseIdleConnections()
		m.mu.Lock()
		clear(m.cache)
		clear(m.jobs)
		m.lru.Init()
		clear(m.lruIndex)
		m.cleanupCursor = nil
		m.expired.Init()
		clear(m.expiredIndex)
		m.mu.Unlock()
	})
	return nil
}
