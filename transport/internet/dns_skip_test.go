package internet_test

import (
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

func TestSkipDNSServers(t *testing.T) {
	internet.SkipDNSServers([]netip.Addr{netip.MustParseAddr("::ffff:203.0.113.53"), netip.MustParseAddr("2001:db8::53")})
	t.Cleanup(func() { internet.SkipDNSServers(nil) })
	for address, want := range map[string]bool{
		"203.0.113.53:53":   true,
		"[2001:db8::53]:53": true,
		"198.51.100.53:53":  false,
		"localhost:53":      false,
	} {
		if got := internet.IsSkippedDNSServer(address); got != want {
			t.Errorf("IsSkippedDNSServer(%q) = %v, want %v", address, got, want)
		}
	}
	internet.SkipDNSServers(nil)
	if internet.IsSkippedDNSServer("203.0.113.53:53") {
		t.Error("still skipped after SkipDNSServers(nil)")
	}
}
