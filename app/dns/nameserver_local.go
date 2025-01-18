package dns

import (
	"context"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer struct {
	client        *localdns.Client
	queryStrategy QueryStrategy
}

const errEmptyResponse = "No address associated with hostname"

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(ctx context.Context, domain string, _ net.IP, option dns.IPOption, _ bool) (ips []net.IP, err error) {
	option = ResolveIpOptionOverride(s.queryStrategy, option)
	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, dns.ErrEmptyResponse
	}

	start := time.Now()
	ips, err = s.client.LookupIP(domain, option)

	if err != nil && strings.HasSuffix(err.Error(), errEmptyResponse) {
		err = dns.ErrEmptyResponse
	}

	// If ipv4 or ipv6 is disabled, filter out the unwanted IPs
	if err != nil && (!option.IPv4Enable || !option.IPv6Enable) {
		var FilteredIPs []net.IP
		for _, ip := range ips {
			if option.IPv4Enable && len(ip) == net.IPv4len {
				FilteredIPs = append(FilteredIPs, ip)
			}
			if option.IPv6Enable && len(ip) == net.IPv6len {
				FilteredIPs = append(FilteredIPs, ip)
			}
		}
		if len(FilteredIPs) == 0 {
			err = dns.ErrEmptyResponse
		}
		ips = FilteredIPs
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
func NewLocalNameServer(queryStrategy QueryStrategy) *LocalNameServer {
	errors.LogInfo(context.Background(), "DNS: created localhost client")
	return &LocalNameServer{
		queryStrategy: queryStrategy,
		client:        localdns.New(),
	}
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient() *Client {
	return &Client{server: NewLocalNameServer(QueryStrategy_USE_IP)}
}
