package localdns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

func TestSkippedDNSServers(t *testing.T) {
	internet.SkipDNSServers([]netip.Addr{netip.MustParseAddr("203.0.113.53")})
	t.Cleanup(func() { internet.SkipDNSServers(nil) })
	c := New()
	if _, err := c.r.Dial(context.Background(), "udp", "203.0.113.53:53"); err == nil {
		t.Error("a skipped DNS server was dialed")
	}
	conn, err := c.r.Dial(context.Background(), "udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
