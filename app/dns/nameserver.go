package dns

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// Client is the interface for DNS client.
type Client interface {
	// Name of the Client.
	Name() string

	// QueryIP sends IP queries to its configured server.
	QueryIP(ctx context.Context, domain string, option dns.IPOption) ([]net.IP, error)
}

type LocalNameServer struct {
	client *localdns.Client
}

func (s *LocalNameServer) QueryIP(_ context.Context, domain string, option dns.IPOption) ([]net.IP, error) {
	if option.IPv4Enable || option.IPv6Enable {
		return s.client.LookupIP(domain, option)
	}

	return nil, newError("neither IPv4 nor IPv6 is enabled")
}

func (s *LocalNameServer) Name() string {
	return "localhost"
}

func NewLocalNameServer() *LocalNameServer {
	newError("DNS: created localhost client").AtInfo().WriteToLog()
	return &LocalNameServer{
		client: localdns.New(),
	}
}
