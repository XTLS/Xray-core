// Package remote implements a FakeDNS engine backed by a single remote allocator.
package remote

import (
	"context"
	"fmt"
	stdnet "net"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dns/fakedns/command"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type pools struct {
	ranges []netip.Prefix
}

// Engine shares mappings, not a replica or a cache: reverse lookups always reach
// the authority, so an evicted address cannot retain a stale local domain.
type Engine struct {
	client    command.FakeDNSServiceClient
	conn      *grpc.ClientConn
	network   string
	address   string
	lifecycle sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	timeout   time.Duration
	pools     atomic.Pointer[pools]
}

var (
	_ dns.FakeDNSEngineRev0    = (*Engine)(nil)
	_ dns.FakeDNSPoolProvider  = (*Engine)(nil)
	_ dns.FakeDNSEngineContext = (*Engine)(nil)
)

// New configures a direct connection to a local API endpoint.
// No traffic is sent until Start; the connection is shared by all mapping calls.
func New(ctx context.Context, address string, timeout uint32) (*Engine, error) {
	network, endpoint, err := localEndpoint(address)
	if err != nil {
		return nil, err
	}
	if timeout == 0 {
		timeout = 2000
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Engine{
		network: network, address: endpoint,
		ctx: ctx, cancel: cancel, timeout: time.Duration(timeout) * time.Millisecond,
	}, nil
}

// Resolve no hostnames and bypass proxy discovery: mapping traffic must stay on
// the same machine even when the environment configures an HTTP/SOCKS proxy.
func localEndpoint(address string) (string, string, error) {
	if strings.HasPrefix(address, "unix:") {
		u, err := url.Parse(address)
		if err == nil && u.Host == "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
			name := u.Path
			if name == "" {
				name = u.Opaque
			}
			if path.IsAbs(name) || filepath.IsAbs(name) {
				return "unix", name, nil
			}
		}
	} else if endpoint, err := netip.ParseAddrPort(address); err == nil && endpoint.Addr().IsLoopback() && endpoint.Addr().Zone() == "" && endpoint.Port() != 0 {
		return "tcp", endpoint.String(), nil
	}
	return "", "", fmt.Errorf("remote FakeDNS requires a loopback IP:port or an absolute unix:/// socket path")
}

func (*Engine) Type() interface{} { return (*dns.FakeDNSEngine)(nil) }

func (e *Engine) Start() error {
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if e.conn != nil {
		return nil
	}
	conn, err := grpc.NewClient("passthrough:///fakedns", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (stdnet.Conn, error) {
			return (&stdnet.Dialer{}).DialContext(ctx, e.network, e.address)
		}))
	if err != nil {
		return err
	}
	// Construction is resource-free. A failed Start owns and closes its candidate
	// connection even when the caller discards the failed core without Close.
	defer func() {
		if e.conn == nil {
			conn.Close()
		}
	}()
	client := command.NewFakeDNSServiceClient(conn)
	ctx, cancel := context.WithTimeout(e.ctx, e.timeout)
	defer cancel()
	response, err := client.GetPools(ctx, &command.GetPoolsRequest{})
	if err != nil {
		return fmt.Errorf("get remote FakeDNS pools: %w", err)
	}
	p := &pools{}
	for _, cidr := range response.IpPools {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid remote FakeDNS pool: %q", cidr)
		}
		p.ranges = append(p.ranges, prefix.Masked())
	}
	if len(p.ranges) == 0 {
		return fmt.Errorf("remote FakeDNS has no pools")
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	e.conn = conn
	e.client = client
	// Publish the immutable client together with its validated ranges.
	e.pools.Store(p)
	return nil
}

func (e *Engine) Close() error {
	e.cancel()
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	if e.conn != nil {
		conn := e.conn
		e.conn = nil
		return conn.Close()
	}
	return nil
}

func (e *Engine) GetFakeIPRanges() []string {
	var ranges []string
	if p := e.pools.Load(); p != nil {
		for _, prefix := range p.ranges {
			ranges = append(ranges, prefix.String())
		}
	}
	return ranges
}

func (e *Engine) IsIPInIPPool(ip net.Address) bool {
	if ip == nil || !ip.Family().IsIP() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip.IP())
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if p := e.pools.Load(); p != nil {
		for _, prefix := range p.ranges {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) GetFakeIPForDomain(domain string) []net.Address {
	return e.GetFakeIPForDomain3(domain, true, true)
}

func (e *Engine) GetFakeIPForDomain3(domain string, ipv4, ipv6 bool) []net.Address {
	ips, _ := e.Allocate(e.ctx, domain, ipv4, ipv6)
	return ips
}

func (e *Engine) callContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, e.timeout)
	// AfterFunc runs asynchronously even for an already-cancelled lifetime.
	// Reject new calls synchronously instead of letting an RPC win that race.
	if ctx.Err() != nil || e.ctx.Err() != nil {
		cancel()
		return ctx, cancel
	}
	stop := context.AfterFunc(e.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

// Allocate implements dns.FakeDNSEngineContext.
// The legacy feature methods have no context or error return and adapt to it.
func (e *Engine) Allocate(ctx context.Context, domain string, ipv4, ipv6 bool) ([]net.Address, error) {
	if !ipv4 && !ipv6 {
		return nil, nil
	}
	if e.pools.Load() == nil {
		return nil, fmt.Errorf("remote FakeDNS is not started")
	}
	ctx, cancel := e.callContext(ctx)
	defer cancel()
	response, err := e.client.Allocate(ctx, &command.AllocateRequest{Domain: domain, Ipv4: ipv4, Ipv6: ipv6})
	if err != nil {
		return nil, err
	}
	var ips []net.Address
	for _, raw := range response.Ips {
		if len(raw) != 4 && len(raw) != 16 {
			return nil, fmt.Errorf("invalid remote FakeDNS address length")
		}
		ip := net.IPAddress(raw)
		if !e.IsIPInIPPool(ip) || (ip.Family().IsIPv4() && !ipv4) || (ip.Family().IsIPv6() && !ipv6) {
			return nil, fmt.Errorf("remote FakeDNS address is outside the requested pools or families")
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (e *Engine) GetDomainFromFakeDNS(ip net.Address) string {
	domain, _ := e.ReverseLookup(e.ctx, ip)
	return domain
}

func (e *Engine) ReverseLookup(ctx context.Context, ip net.Address) (string, error) {
	if !e.IsIPInIPPool(ip) {
		return "", nil
	}
	ctx, cancel := e.callContext(ctx)
	defer cancel()
	response, err := e.client.ReverseLookup(ctx, &command.ReverseLookupRequest{Ip: ip.IP()})
	if err != nil {
		return "", err
	}
	if domain := response.Domain; domain != "" {
		if _, ok := mdns.IsDomainName(domain); !ok || strings.ContainsAny(domain, "\x00\r\n\t ") {
			return "", fmt.Errorf("invalid remote FakeDNS domain")
		}
	}
	return response.Domain, nil
}
