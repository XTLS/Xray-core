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
// "resolves through the system" from "has an independent upstream", so both
// shapes need to be distinguishable without standing up an instance.
func TestUsesSystemResolver(t *testing.T) {
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
			name:    "an independent name server",
			clients: []*Client{{server: NewLocalNameServer()}, {server: fakeServer{}}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &DNS{clients: tt.clients}
			if got := server.UsesSystemResolver(); got != tt.want {
				t.Errorf("UsesSystemResolver() = %v, want %v", got, tt.want)
			}
		})
	}
}
