package wireguard

import (
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	wgconn "golang.zx2c4.com/wireguard/conn"
)

type capturePacketConn struct {
	writtenAddr stdnet.Addr
}

func (c *capturePacketConn) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (c *capturePacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, nil)
}

func (c *capturePacketConn) Close() error {
	return nil
}

func (c *capturePacketConn) LocalAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4zero, Port: 0}
}

func (c *capturePacketConn) RemoteAddr() stdnet.Addr {
	return nil
}

func (c *capturePacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *capturePacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *capturePacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *capturePacketConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
	return 0, nil, io.EOF
}

func (c *capturePacketConn) WriteTo(p []byte, addr stdnet.Addr) (int, error) {
	c.writtenAddr = addr
	return len(p), nil
}

type captureTunnel struct {
	udpConn *capturePacketConn
}

func (t *captureTunnel) BuildDevice(ipc string, bind wgconn.Bind) error {
	return nil
}

func (t *captureTunnel) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (stdnet.Conn, error) {
	return nil, nil
}

func (t *captureTunnel) DialUDPAddrPort(laddr, raddr netip.AddrPort) (stdnet.Conn, error) {
	return t.udpConn, nil
}

func (t *captureTunnel) Close() error {
	return nil
}

type staticDNSClient struct{}

func (c *staticDNSClient) Type() interface{} {
	return feature_dns.ClientType()
}

func (c *staticDNSClient) Start() error {
	return nil
}

func (c *staticDNSClient) Close() error {
	return nil
}

func (c *staticDNSClient) LookupIP(domain string, option feature_dns.IPOption) ([]stdnet.IP, uint32, error) {
	return []stdnet.IP{stdnet.IPv4(192, 0, 2, 1)}, 0, nil
}

type staticPolicyManager struct{}

func (m staticPolicyManager) Type() interface{} {
	return policy.ManagerType()
}

func (m staticPolicyManager) Start() error {
	return nil
}

func (m staticPolicyManager) Close() error {
	return nil
}

func (m staticPolicyManager) ForLevel(level uint32) policy.Session {
	return policy.SessionDefault()
}

func (m staticPolicyManager) ForSystem() policy.System {
	return policy.System{}
}

type noopDialer struct{}

func (d *noopDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	return nil, nil
}

func (d *noopDialer) DestIpAddress() stdnet.IP {
	return nil
}

func (d *noopDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

func TestProcessStoresResolvedDomainDestinationForUDP(t *testing.T) {
	packetConn := &capturePacketConn{}
	dialer := &noopDialer{}
	handler := &Handler{
		conf:          &DeviceConfig{DomainStrategy: DeviceConfig_FORCE_IP4},
		net:           &captureTunnel{udpConn: packetConn},
		bind:          &netBindClient{dialer: dialer},
		policyManager: staticPolicyManager{},
		dns:           &staticDNSClient{},
		hasIPv4:       true,
	}

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	defer uplinkReader.Interrupt()
	defer uplinkWriter.Close()
	defer downlinkReader.Interrupt()
	defer downlinkWriter.Close()

	payload := buf.FromBytes([]byte("dns query"))
	if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	if err := uplinkWriter.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: xnet.UDPDestination(xnet.DomainAddress("resolver.test"), 53)},
	})
	err := handler.Process(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, dialer)
	if err != nil {
		t.Fatal(err)
	}

	addr, ok := packetConn.writtenAddr.(*stdnet.UDPAddr)
	if !ok {
		t.Fatalf("expected UDPAddr write target, got %T", packetConn.writtenAddr)
	}
	if !addr.IP.Equal(stdnet.IPv4(192, 0, 2, 1)) || addr.Port != 53 {
		t.Fatalf("unexpected write target: %v", addr)
	}

	var _ internet.Dialer = dialer
}
