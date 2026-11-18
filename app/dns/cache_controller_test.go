package dns

import (
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func TestCacheCleanupPreservesLookupRecords(t *testing.T) {
	for _, test := range []struct {
		name        string
		expiredA    bool
		expiredAAAA bool
	}{
		{name: "expired A", expiredA: true},
		{name: "expired AAAA", expiredAAAA: true},
		{name: "both expired", expiredA: true, expiredAAAA: true},
		{name: "both fresh"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := NewCacheController("test", false, false, 0)
			now := time.Now()
			a := &IPRecord{Expire: now.Add(time.Hour)}
			aaaa := &IPRecord{Expire: now.Add(time.Hour)}
			if test.expiredA {
				a.Expire = now.Add(-time.Hour)
			}
			if test.expiredAAAA {
				aaaa.Expire = now.Add(-time.Hour)
			}
			cache.ips["example.test."] = &record{A: a, AAAA: aaaa}

			// A lookup reads these fields after findRecords releases the lock.
			lookup := cache.findRecords("example.test.")
			if err := cache.CacheCleanup(); err != nil {
				t.Fatal(err)
			}
			if lookup.A != a || lookup.AAAA != aaaa {
				t.Fatal("cleanup modified a record already returned to a lookup")
			}

			current := cache.findRecords("example.test.")
			if test.expiredA && test.expiredAAAA {
				if current != nil {
					t.Fatal("fully expired record remains cached")
				}
				return
			}
			if current == nil {
				t.Fatal("cleanup removed an unexpired address family")
			}
			wantA, wantAAAA := a, aaaa
			if test.expiredA {
				wantA = nil
			}
			if test.expiredAAAA {
				wantAAAA = nil
			}
			if current.A != wantA || current.AAAA != wantAAAA {
				t.Fatal("cleanup did not preserve the unexpired address families")
			}
		})
	}
}

func TestCacheCleanupConcurrentLookup(t *testing.T) {
	cache := NewCacheController("test", false, false, 0)
	expired := &IPRecord{IP: []net.IP{net.ParseIP("192.0.2.1")}, Expire: time.Now().Add(-time.Hour)}
	live := &IPRecord{IP: []net.IP{net.ParseIP("2001:db8::1")}, Expire: time.Now().Add(time.Hour)}
	const domain = "example.test."
	cache.ips[domain] = &record{A: expired, AAAA: live}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for range 10000 {
			cache.Lock()
			cache.ips[domain] = &record{A: expired, AAAA: live}
			cache.Unlock()
			if err := cache.CacheCleanup(); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range 10000 {
			rec := cache.findRecords(domain)
			ips, _, err := merge(dns_feature.IPOption{IPv6Enable: true}, rec.A, rec.AAAA)
			if err != nil || len(ips) != 1 || !ips[0].Equal(live.IP[0]) {
				t.Errorf("cached IPv6 lookup: ips=%v err=%v", ips, err)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
}
