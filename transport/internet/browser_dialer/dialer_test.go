package browser_dialer

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseBrowserDialerAddressRequireUUIDPath(t *testing.T) {
	valid := "127.0.0.1:8080/123e4567-e89b-12d3-a456-426614174000"
	if _, _, ok := parseBrowserDialerAddress(valid); !ok {
		t.Fatalf("expected valid browser dialer address: %s", valid)
	}

	invalid := []string{
		"127.0.0.1:8080/example",
		"127.0.0.1:8080/short",
		"127.0.0.1:8080/123e4567e89b12d3a456426614174000",
		"127.0.0.1:8080/123e4567-e89b-12d3-a456-426614174000/extra",
	}
	for _, addr := range invalid {
		if _, _, ok := parseBrowserDialerAddress(addr); ok {
			t.Fatalf("expected invalid browser dialer address: %s", addr)
		}
	}
}

func TestGetDialerByAddressReusesExistingServerForSameListenAddress(t *testing.T) {
	listenAddr := "127.0.0.1:39000"
	server := &dialerServer{
		server:     &http.Server{Addr: listenAddr},
		pageRoutes: make(map[string]*dialerInstance),
	}

	mu.Lock()
	oldDialers, oldServers := sockoptDialers, dialerServers
	sockoptDialers = make(map[string]*dialerInstance)
	dialerServers = map[string]*dialerServer{listenAddr: server}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		sockoptDialers = oldDialers
		dialerServers = oldServers
		mu.Unlock()
	})

	if _, err := getDialerByAddress(listenAddr + "/123e4567-e89b-12d3-a456-426614174000"); err != nil {
		t.Fatalf("failed to create first dialer: %v", err)
	}
	if _, err := getDialerByAddress(listenAddr + "/123e4567-e89b-12d3-a456-426614174001"); err != nil {
		t.Fatalf("failed to create second dialer on same listener: %v", err)
	}
	if len(dialerServers) != 1 {
		t.Fatalf("expected one shared listener, got %d", len(dialerServers))
	}
}

func TestGetDialerByAddressRejectsSamePortDifferentAddress(t *testing.T) {
	listenAddr := "127.0.0.1:39001"
	server := &dialerServer{
		server:     &http.Server{Addr: listenAddr},
		pageRoutes: make(map[string]*dialerInstance),
	}

	mu.Lock()
	oldDialers, oldServers := sockoptDialers, dialerServers
	sockoptDialers = make(map[string]*dialerInstance)
	dialerServers = map[string]*dialerServer{listenAddr: server}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		sockoptDialers = oldDialers
		dialerServers = oldServers
		mu.Unlock()
	})

	_, err := getDialerByAddress("127.0.0.2:39001/123e4567-e89b-12d3-a456-426614174011")
	if err == nil {
		t.Fatal("expected error for same port with different listen address")
	}
	if !strings.Contains(err.Error(), "cannot use the same port with a different listen address") {
		t.Fatalf("unexpected error: %v", err)
	}
}
