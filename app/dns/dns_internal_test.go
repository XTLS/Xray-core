package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	feature_dns "github.com/xtls/xray-core/features/dns"
)

// fakeServer stands in for any name server that is not the system resolver.
type fakeServer struct{}

func (fakeServer) Name() string         { return "fake" }
func (fakeServer) IsDisableCache() bool { return false }
func (fakeServer) QueryIP(context.Context, string, feature_dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, nil
}

// Callers that are about to redirect the system resolver rely on this to tell
// whether any resolution path could still reach the system resolver, so the
// mixed shape has to be reported as reachable: a domain-specific rule can
// select the system resolver even when an independent upstream also exists.
func TestMayUseSystemResolver(t *testing.T) {
	tests := []struct {
		name    string
		clients []*Client
		want    bool
	}{
		{
			name: "no clients at all",
			want: true,
		},
		{
			name:    "only the system resolver",
			clients: []*Client{{server: NewLocalNameServer()}},
			want:    true,
		},
		{
			name:    "the system resolver alongside an independent name server",
			clients: []*Client{{server: fakeServer{}}, {server: NewLocalNameServer()}},
			want:    true,
		},
		{
			name:    "only independent name servers",
			clients: []*Client{{server: fakeServer{}}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &DNS{clients: tt.clients}
			if got := server.MayUseSystemResolver(); got != tt.want {
				t.Errorf("MayUseSystemResolver() = %v, want %v", got, tt.want)
			}
		})
	}
}
