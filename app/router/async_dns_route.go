package router

import (
	"bytes"
	"encoding/json"
	"io"
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
)

type asyncDNSCacheEntry struct {
	routeRU bool
	expires time.Time
}

type asyncDNSClassifierRequest struct {
	Domain string `json:"domain"`
}

type asyncDNSClassifierResponse struct {
	State            string `json:"state"`
	Route            string `json:"route"`
	TTLMillis        uint32 `json:"ttlMillis"`
	RetryAfterMillis uint32 `json:"retryAfterMillis"`
}

// AsyncDNSRouteMatcher maintains a bounded L1 projection of the shared L2
// classifier cache. Apply is deliberately non-blocking: a miss only queues a
// background request and returns false so the normal fallback rule wins.
type AsyncDNSRouteMatcher struct {
	endpoint      string
	bearerToken   string
	client        *http.Client
	cacheCapacity int
	minTTL        time.Duration
	maxTTL        time.Duration
	queue         chan string
	stop          chan struct{}
	workers       sync.WaitGroup
	closed        atomic.Bool
	closeOnce     sync.Once

	mu       sync.Mutex
	cache    map[string]asyncDNSCacheEntry
	inflight map[string]struct{}
	retryAt  map[string]time.Time
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
	if bearerToken != "" && (endpoint.Scheme != "https" || endpoint.User != nil) {
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

	m := &AsyncDNSRouteMatcher{
		endpoint:    endpoint.String(),
		bearerToken: bearerToken,
		client: &http.Client{
			Timeout: requestTimeout,
			// Never forward service credentials to a redirect destination.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cacheCapacity: cacheCapacity,
		minTTL:        minTTL,
		maxTTL:        maxTTL,
		queue:         make(chan string, queueCapacity),
		stop:          make(chan struct{}),
		cache:         make(map[string]asyncDNSCacheEntry, cacheCapacity),
		inflight:      make(map[string]struct{}),
		retryAt:       make(map[string]time.Time),
	}
	m.workers.Add(workerCount)
	for range workerCount {
		go m.runWorker()
	}
	return m, nil
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

// Apply returns true only for a fresh RU classification. It never waits for a
// DNS answer or for the shared cache endpoint.
func (m *AsyncDNSRouteMatcher) Apply(ctx routing.Context) bool {
	domain := normalizeAsyncDNSDomain(ctx.GetTargetDomain())
	if domain == "" || m.closed.Load() {
		return false
	}

	now := time.Now()
	m.mu.Lock()
	if entry, found := m.cache[domain]; found {
		if now.Before(entry.expires) {
			m.mu.Unlock()
			return entry.routeRU
		}
		delete(m.cache, domain)
	}
	if retryAt, found := m.retryAt[domain]; found && now.Before(retryAt) {
		m.mu.Unlock()
		return false
	}
	if _, found := m.inflight[domain]; found {
		m.mu.Unlock()
		return false
	}
	m.inflight[domain] = struct{}{}
	select {
	case m.queue <- domain:
		m.mu.Unlock()
	default:
		delete(m.inflight, domain)
		m.retryAt[domain] = now.Add(defaultAsyncDNSRetry)
		m.mu.Unlock()
	}
	return false
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
			m.refresh(domain)
		}
	}
}

func (m *AsyncDNSRouteMatcher) refresh(domain string) {
	response, err := m.fetch(domain)
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.inflight, domain)
	if err != nil {
		m.retryAt[domain] = now.Add(defaultAsyncDNSRetry)
		return
	}

	switch response.State {
	case "ready":
		if response.Route != "ru" && response.Route != "other" {
			m.retryAt[domain] = now.Add(defaultAsyncDNSRetry)
			return
		}
		m.evictIfNeeded(now)
		m.cache[domain] = asyncDNSCacheEntry{
			routeRU: response.Route == "ru",
			expires: now.Add(m.clampTTL(durationOrDefault(response.TTLMillis, m.minTTL))),
		}
		delete(m.retryAt, domain)
	case "pending":
		m.retryAt[domain] = now.Add(durationOrDefault(response.RetryAfterMillis, defaultAsyncDNSRetry))
	default:
		m.retryAt[domain] = now.Add(defaultAsyncDNSRetry)
	}
}

func (m *AsyncDNSRouteMatcher) evictIfNeeded(now time.Time) {
	if len(m.cache) < m.cacheCapacity {
		return
	}
	for domain, entry := range m.cache {
		if !now.Before(entry.expires) {
			delete(m.cache, domain)
			return
		}
	}
	for domain := range m.cache {
		delete(m.cache, domain)
		return
	}
}

func (m *AsyncDNSRouteMatcher) clampTTL(ttl time.Duration) time.Duration {
	if ttl < m.minTTL {
		return m.minTTL
	}
	if ttl > m.maxTTL {
		return m.maxTTL
	}
	return ttl
}

func (m *AsyncDNSRouteMatcher) fetch(domain string) (*asyncDNSClassifierResponse, error) {
	body, err := json.Marshal(asyncDNSClassifierRequest{Domain: domain})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if m.bearerToken != "" {
		if req.URL.Scheme != "https" || req.URL.User != nil {
			return nil, errors.New("refusing async DNS bearer token over an insecure endpoint")
		}
		req.Header.Set("Authorization", "Bearer "+m.bearerToken)
	}
	response, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("async DNS route classifier returned status ", response.StatusCode)
	}

	decoded := new(asyncDNSClassifierResponse)
	if err := json.NewDecoder(io.LimitReader(response.Body, 32*1024)).Decode(decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func (m *AsyncDNSRouteMatcher) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		close(m.stop)
		m.workers.Wait()
	})
	return nil
}
