package dns

import (
	"context"
	"strings"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/log"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/features/dns"
	"github.com/GFW-knocker/Xray-core/features/dns/localdns"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer struct {
	client *localdns.Client
}

const errEmptyResponse = "No address associated with hostname"

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(ctx context.Context, domain string, _ net.IP, option dns.IPOption, _ bool) (ips []net.IP, err error) {
	start := time.Now()
	ips, err = s.client.LookupIP(domain, option)

	if err != nil && strings.HasSuffix(err.Error(), errEmptyResponse) {
		err = dns.ErrEmptyResponse
	}

	if len(ips) > 0 {
		errors.LogInfo(ctx, "Localhost got answer: ", domain, " -> ", ips)
		log.Record(&log.DNSLog{Server: s.Name(), Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	}

	return
}

// Name implements Server.
func (s *LocalNameServer) Name() string {
	return "localhost"
}

// NewLocalNameServer creates localdns server object for directly lookup in system DNS.
func NewLocalNameServer() *LocalNameServer {
	errors.LogInfo(context.Background(), "DNS: created localhost client")
	return &LocalNameServer{
		client: localdns.New(),
	}
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient() *Client {
	return &Client{server: NewLocalNameServer()}
}
