package internet

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/net"
)

// DNS pinning is an opt-in, per-context mechanism to keep repeated dials to the
// same domain using a stable chosen IP (e.g. for XHTTP upload/download legs).

type dnsPinKey struct{}

type dnsPinStore struct {
	mu sync.Mutex
	m  map[string]net.IP // normalized domain -> pinned IP
}

func normalizePinDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(d, ".")
}

// ContextWithDNSPin returns a derived context that enables DNS pinning.
// DialSystem will only honor pins when the context carries a pin store.
func ContextWithDNSPin(ctx context.Context) context.Context {
	if ctx.Value(dnsPinKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, dnsPinKey{}, &dnsPinStore{m: make(map[string]net.IP)})
}

func getDNSPin(ctx context.Context, domain string) (net.IP, bool) {
	store, ok := ctx.Value(dnsPinKey{}).(*dnsPinStore)
	if !ok || store == nil {
		return nil, false
	}
	d := normalizePinDomain(domain)
	if d == "" {
		return nil, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	ip, ok := store.m[d]
	if !ok || len(ip) == 0 {
		return nil, false
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out, true
}

// SetDNSPinIfAbsent pins domain -> ip if no pin exists yet.
// Returns true if it was stored.
func SetDNSPinIfAbsent(ctx context.Context, domain string, ip net.IP) bool {
	store, ok := ctx.Value(dnsPinKey{}).(*dnsPinStore)
	if !ok || store == nil {
		return false
	}
	d := normalizePinDomain(domain)
	if d == "" || len(ip) == 0 {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.m[d]; ok && len(existing) > 0 {
		return false
	}
	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	store.m[d] = ipCopy
	return true
}


