package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/routing"
)

type domainInputContext struct {
	routing.Context
	domain string
}

func (c domainInputContext) GetTargetDomain() string { return c.domain }

func TestAsyncDNSDomainInputMatchesClassifierContract(t *testing.T) {
	valid := map[string]string{
		" Example.COM. ": "example.com", "localhost": "localhost", "_sip._tcp.example": "_sip._tcp.example",
		"xn--e1afmkfd.xn--p1ai": "xn--e1afmkfd.xn--p1ai", "a-b.example": "a-b.example",
		strings.Repeat("a", 63) + ".example": strings.Repeat("a", 63) + ".example",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61): strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	}
	for input, want := range valid {
		if got := normalizeAsyncDNSDomain(input); got != want {
			t.Errorf("valid input rejected: got %q want %q", got, want)
		}
	}
	for _, input := range invalidDomainInputs() {
		if got := normalizeAsyncDNSDomain(input); got != "" {
			t.Errorf("invalid synthetic shape accepted: %q", got)
		}
	}
}

func invalidDomainInputs() []string {
	return []string{
		"", " . ", "synthetic..invalid", ".example", "example..", "-bad.example", "bad-.example", "bad name.example", "bad/name.example", "bad:443", "https://example", "*.example", "пример.рф", "例子.example", "127.0.0.1", "192.0.2.1.", "::1", "[::1]", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 254),
	}
}

func TestAsyncDNSInvalidDomainInputDoesNotCreateJobsOrHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "invalid domain", 400) }))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL, RequestTimeoutMillis: 150})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for range 3 {
		for _, domain := range invalidDomainInputs() {
			if m.Apply(domainInputContext{domain: domain}) {
				t.Fatal("invalid target changed fallback route")
			}
		}
	}
	// Exceed the existing250ms minimum retry interval; no job must reach scheduler.
	time.Sleep(300 * time.Millisecond)
	s := m.Stats()
	if calls.Load() != 0 || s.Requests != 0 || s.Errors != 0 || s.Jobs != 0 || s.Queued != 0 || s.Misses != 0 || s.WaitStarts != 0 {
		t.Fatalf("invalid target created classifier work: %+v", s)
	}
}

func TestAsyncDNSDomainInputPreservesValidL1AndRejectsInvalidInheritedEntry(t *testing.T) {
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "https://classifier.invalid/v1/classify"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	until := time.Now().Add(time.Minute)
	m.mu.Lock()
	m.cache["ru.example"] = asyncDNSCacheEntry{routeRU: true, freshUntil: until, hardUntil: until, refreshAt: until}
	m.cache["other.example"] = asyncDNSCacheEntry{routeRU: false, freshUntil: until, hardUntil: until, refreshAt: until}
	m.cache["synthetic..invalid"] = asyncDNSCacheEntry{routeRU: true, freshUntil: until, hardUntil: until, refreshAt: until}
	m.mu.Unlock()
	if !m.Apply(domainInputContext{domain: " RU.EXAMPLE. "}) || m.Apply(domainInputContext{domain: "other.example"}) {
		t.Fatal("valid cached routing changed")
	}
	if m.Apply(domainInputContext{domain: "synthetic..invalid"}) {
		t.Fatal("invalid inherited key acquired a route")
	}
	if s := m.Stats(); s.FreshHits != 2 || s.Requests != 0 || s.Jobs != 0 {
		t.Fatalf("L1 or fallback behavior changed: %+v", s)
	}
	// The validity check does not evict unrelated persisted/L1 entries.
	if len(m.cache) != 3 {
		t.Fatal("domain preflight mutated L1 state")
	}
}

func TestAsyncDNSSnapshotDomainInputCompatibilityAndWholePayloadRejection(t *testing.T) {
	now := time.Now()
	entry := func(domain string) asyncDNSSnapshotEntry {
		return asyncDNSSnapshotEntry{Domain: domain, RouteRU: true, FreshUntil: now.Add(time.Second), HardUntil: now.Add(2 * time.Second), ServerHardUntil: now.Add(3 * time.Second), LastUsed: now, RefreshAt: now.Add(time.Second)}
	}
	payload := asyncDNSSnapshotPayload{Version: asyncDNSSnapshotVersion, Identity: "domain-input-contract", SavedAt: now, Entries: []asyncDNSSnapshotEntry{entry("valid.example"), entry("_sip._tcp.example"), entry("xn--e1afmkfd.xn--p1ai")}}
	encoded, err := encodeAsyncDNSSnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeAsyncDNSSnapshot(encoded, payload.Identity, now, 4096, time.Minute)
	if err != nil || len(restored) != 3 {
		t.Fatal("valid existing snapshot compatibility changed")
	}
	for _, domain := range []string{"synthetic..invalid", "192.0.2.1", "пример.рф"} {
		malformed := payload
		malformed.Entries = append(append([]asyncDNSSnapshotEntry(nil), payload.Entries...), entry(domain))
		encoded, err = encodeAsyncDNSSnapshot(malformed)
		if err != nil {
			t.Fatal(err)
		}
		restored, err = decodeAsyncDNSSnapshot(encoded, payload.Identity, now, 4096, time.Minute)
		if err == nil || restored != nil {
			t.Fatal("malformed old snapshot must fail closed as a whole, not partially restore")
		}
	}
}
