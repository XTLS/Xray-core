package dispatcher

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestShouldSniff(t *testing.T) {
	excluded := net.MemoryPortList{{From: 22, To: 22}, {From: 993, To: 995}}

	cases := []struct {
		name    string
		request session.SniffingRequest
		port    net.Port
		want    bool
	}{
		{"sniffing disabled", session.SniffingRequest{}, 443, false},
		{"disabled and excluded", session.SniffingRequest{ExcludeForPort: excluded}, 22, false},
		{"nothing excluded", session.SniffingRequest{Enabled: true}, 443, true},
		{"single port excluded", session.SniffingRequest{Enabled: true, ExcludeForPort: excluded}, 22, false},
		{"range start excluded", session.SniffingRequest{Enabled: true, ExcludeForPort: excluded}, 993, false},
		{"range end excluded", session.SniffingRequest{Enabled: true, ExcludeForPort: excluded}, 995, false},
		{"just past the range", session.SniffingRequest{Enabled: true, ExcludeForPort: excluded}, 996, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			destination := net.TCPDestination(net.LocalHostIP, c.port)
			if got := shouldSniff(c.request, destination); got != c.want {
				t.Errorf("shouldSniff(port %v) = %v, want %v", c.port, got, c.want)
			}
		})
	}
}
