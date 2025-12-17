package internet

import (
	"context"
	"errors"
	"testing"
	"time"

	cnet "github.com/xtls/xray-core/common/net"
	feature_dns "github.com/xtls/xray-core/features/dns"
)

type fakeDNSClient struct {
	ips []cnet.IP
}

func (f *fakeDNSClient) Type() interface{} { return feature_dns.ClientType() }
func (f *fakeDNSClient) Start() error      { return nil }
func (f *fakeDNSClient) Close() error      { return nil }
func (f *fakeDNSClient) LookupIP(domain string, option feature_dns.IPOption) ([]cnet.IP, uint32, error) {
	return append([]cnet.IP(nil), f.ips...), 60, nil
}

type recordDialer struct {
	dests []cnet.Destination
}

func (d *recordDialer) Type() interface{} { return (*recordDialer)(nil) }
func (d *recordDialer) DestIpAddress() cnet.IP {
	return nil
}
func (d *recordDialer) Dial(ctx context.Context, source cnet.Address, destination cnet.Destination, sockopt *SocketConfig) (cnet.Conn, error) {
	d.dests = append(d.dests, destination)
	return &noopConn{remote: destination}, nil
}

type noopConn struct {
	remote cnet.Destination
	closed bool
}

func (c *noopConn) Read([]byte) (int, error)  { return 0, errors.New("noop") }
func (c *noopConn) Write([]byte) (int, error) { return 0, errors.New("noop") }
func (c *noopConn) Close() error              { c.closed = true; return nil }
func (c *noopConn) LocalAddr() cnet.Addr      { return &cnet.TCPAddr{IP: []byte{0, 0, 0, 0}, Port: 0} }
func (c *noopConn) RemoteAddr() cnet.Addr {
	return &cnet.TCPAddr{IP: c.remote.Address.IP(), Port: int(c.remote.Port)}
}
func (c *noopConn) SetDeadline(time.Time) error      { return nil }
func (c *noopConn) SetReadDeadline(time.Time) error  { return nil }
func (c *noopConn) SetWriteDeadline(time.Time) error { return nil }

func TestDialSystem_DNSPin_OptInPinsChosenIPAcrossDials(t *testing.T) {
	// Arrange: mock DNS returns two IPs; mock dialer records destinations instead of dialing.
	oldDNS := dnsClient
	oldDialer := effectiveSystemDialer
	defer func() {
		dnsClient = oldDNS
		effectiveSystemDialer = oldDialer
	}()

	sockopt := &SocketConfig{DomainStrategy: DomainStrategy_USE_IP}
	dest443 := cnet.TCPDestination(cnet.DomainAddress("example.com"), 443)
	dest8443 := cnet.TCPDestination(cnet.DomainAddress("example.com"), 8443)

	// Without pin store: DialSystem should respect current DNS results (deterministic with 1 IP).
	{
		rd := &recordDialer{}
		effectiveSystemDialer = rd
		dnsClient = &fakeDNSClient{ips: []cnet.IP{{1, 1, 1, 1}}}
		_, _ = DialSystem(context.Background(), dest443, sockopt)
		dnsClient = &fakeDNSClient{ips: []cnet.IP{{2, 2, 2, 2}}}
		_, _ = DialSystem(context.Background(), dest443, sockopt)
		if len(rd.dests) != 2 {
			t.Fatalf("expected 2 dials, got %d", len(rd.dests))
		}
		if rd.dests[0].Address.String() != "1.1.1.1" {
			t.Fatalf("expected first dial to use 1.1.1.1, got %s", rd.dests[0].Address)
		}
		if rd.dests[1].Address.String() != "2.2.2.2" {
			t.Fatalf("expected second dial to use 2.2.2.2 after DNS change, got %s", rd.dests[1].Address)
		}
	}

	// With pin store: second call must reuse the first chosen IP even if DNS changes and port differs.
	{
		rd := &recordDialer{}
		effectiveSystemDialer = rd
		ctx := ContextWithDNSPin(context.Background())
		dnsClient = &fakeDNSClient{ips: []cnet.IP{{1, 1, 1, 1}}}
		_, _ = DialSystem(ctx, dest443, sockopt)
		dnsClient = &fakeDNSClient{ips: []cnet.IP{{2, 2, 2, 2}}}
		_, _ = DialSystem(ctx, dest8443, sockopt)
		if len(rd.dests) != 2 {
			t.Fatalf("expected 2 dials, got %d", len(rd.dests))
		}
		if rd.dests[0].Address.String() != "1.1.1.1" {
			t.Fatalf("expected first dial to use 1.1.1.1, got %s", rd.dests[0].Address)
		}
		if rd.dests[1].Address.String() != "1.1.1.1" {
			t.Fatalf("expected pinned IP to be reused after DNS change, got %s", rd.dests[1].Address)
		}
		if rd.dests[0].Port == rd.dests[1].Port {
			t.Fatalf("expected ports to differ to prove pinning is independent of port, got %s", rd.dests[0].Port)
		}
	}
}
