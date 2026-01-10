package stats

import (
	"fmt"
	"sync"
	"testing"
)

func TestOnlineMap_MaxIPs(t *testing.T) {
	om := NewOnlineMap()
	om.SetMaxIPs(3)

	if !om.TryAddIP("1.1.1.1") {
		t.Error("Expected to allow 1.1.1.1")
	}
	if !om.TryAddIP("2.2.2.2") {
		t.Error("Expected to allow 2.2.2.2")
	}
	if !om.TryAddIP("3.3.3.3") {
		t.Error("Expected to allow 3.3.3.3")
	}
	if om.TryAddIP("4.4.4.4") {
		t.Error("Expected to reject 4.4.4.4 (over limit)")
	}
	if !om.TryAddIP("1.1.1.1") {
		t.Error("Expected to allow existing IP 1.1.1.1")
	}
}

func TestOnlineMap_NoLimit(t *testing.T) {
	om := NewOnlineMap()

	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if !om.TryAddIP(ip) {
			t.Errorf("Expected to allow IP %s with no limit", ip)
		}
	}
}

func TestOnlineMap_Localhost(t *testing.T) {
	om := NewOnlineMap()
	om.SetMaxIPs(1)
	om.TryAddIP("1.1.1.1")

	if !om.TryAddIP("127.0.0.1") {
		t.Error("Expected to always allow localhost")
	}
}

func TestOnlineMap_ConcurrentTryAddIP(t *testing.T) {
	om := NewOnlineMap()
	om.SetMaxIPs(3)

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.1.%d", n%10)
			om.TryAddIP(ip)
		}(i)
	}

	wg.Wait()

	if om.Count() > 3 {
		t.Errorf("Expected at most 3 IPs, got %d", om.Count())
	}
}

func TestOnlineMap_TOCTOU_Race(t *testing.T) {
	om := NewOnlineMap()
	om.SetMaxIPs(1)

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", n%256)
			om.TryAddIP(ip)
		}(i)
	}

	wg.Wait()

	if om.Count() > 1 {
		t.Errorf("TOCTOU race detected! Expected at most 1 IP, got %d", om.Count())
	}
}

func TestOnlineMap_DataRaceFree(t *testing.T) {
	om := NewOnlineMap()
	om.SetMaxIPs(10)

	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(4)

		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("172.16.%d.%d", n/256, n%256)
			om.TryAddIP(ip)
		}(i)

		go func() {
			defer wg.Done()
			_ = om.Count()
		}()

		go func() {
			defer wg.Done()
			_ = om.List()
		}()

		go func(n int) {
			defer wg.Done()
			om.SetMaxIPs(5 + n%5)
		}(i)
	}

	wg.Wait()
}
