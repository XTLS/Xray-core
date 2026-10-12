package xdns

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func startDoH3TestGateway(t *testing.T, handler http.Handler) (string, *ResolverProto, *finalmask.Dialer) {
	t.Helper()
	cert, ca := resolverTestCertificate(t)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: packetConn}
	listener, err := transport.Listen(http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}), &quic.Config{Allow0RTT: false})
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		t.Fatal(err)
	}
	server := &http3.Server{Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ServeListener(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = transport.Close()
		_ = packetConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("H3 gateway did not exit")
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https+h3://resolver.test:" + port + "/dns%2Dquery?token=a%2Fb&x=1&x=2"
	config := &ResolverProto{
		Type: "https+h3", Addr: endpoint, Bootstrap: "127.0.0.1",
		Certificates: []*xtls.Certificate{{Usage: xtls.Certificate_AUTHORITY_VERIFY, Certificate: ca}},
	}
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if dest.Network != xnet.Network_UDP || dest.Address.String() != "127.0.0.1" || strconv.Itoa(int(dest.Port)) != port {
			t.Errorf("wrong H3 bootstrap destination: %v", dest)
		}
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &xnet.PacketConnWrapper{PacketConn: conn, Dest: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(dest.Port)}}, nil
	}}
	return endpoint, config, dialer
}

func TestDoH3WireAndReuse(t *testing.T) {
	testHTTPResolverWire(t, NewDoH3Resolver, startDoH3TestGateway, 3)
}

func TestDoH3OutOfOrder(t *testing.T) {
	testHTTPResolverOutOfOrder(t, NewDoH3Resolver, startDoH3TestGateway)
}

func TestDoH3CloseCancelsBody(t *testing.T) {
	testHTTPResolverClose(t, NewDoH3Resolver, startDoH3TestGateway)
}
func TestDoH3CloseCancelsDial(t *testing.T) { testHTTPResolverCloseDial(t, NewDoH3Resolver, true) }
func TestDoH3RequestErrorsDoNotStopRead(t *testing.T) {
	testHTTPResolverErrors(t, NewDoH3Resolver, startDoH3TestGateway)
}

func TestDoH3ReconnectsWithoutReplay(t *testing.T) {
	testHTTPResolverReconnect(t, NewDoH3Resolver, startDoH3TestGateway, 3)
}

type httpTestTrackedPacketConn struct {
	net.PacketConn
	closes atomic.Int32
	once   sync.Once
	closed chan struct{}
}

func (c *httpTestTrackedPacketConn) Close() error {
	var err error
	c.once.Do(func() {
		c.closes.Add(1)
		err = c.PacketConn.Close()
		if c.closed != nil {
			close(c.closed)
		}
	})
	return err
}

func TestDoH3ClosesPacketConnAfterHandshakeFailure(t *testing.T) {
	for _, failure := range []string{"untrusted", "hostname"} {
		t.Run(failure, func(t *testing.T) {
			_, config, dialer := startDoH3TestGateway(t, http.NotFoundHandler())
			if failure == "untrusted" {
				config.Certificates = nil
			} else {
				config.Addr = strings.Replace(config.Addr, "resolver.test", "wrong.example", 1)
			}
			dial := dialer.DialUDPContext
			created := make(chan *httpTestTrackedPacketConn, 1)
			dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
				conn, err := dial(ctx, dest)
				if err != nil {
					return nil, err
				}
				wrapper := conn.(*xnet.PacketConnWrapper)
				tracked := &httpTestTrackedPacketConn{PacketConn: wrapper.PacketConn}
				wrapper.PacketConn = tracked
				created <- tracked
				return wrapper, nil
			}
			resolver, err := NewDoH3Resolver(config, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(resolver.Close)
			if err := resolver.Send(httpTestQuery(t, 1, "untrusted.example.")); err != nil {
				t.Fatal(err)
			}
			var conn *httpTestTrackedPacketConn
			select {
			case conn = <-created:
			case <-time.After(time.Second):
				t.Fatal("H3 did not use finalmask DialUDPContext")
			}
			deadline := time.After(3 * time.Second)
			ticker := time.NewTicker(time.Millisecond * 10)
			defer ticker.Stop()
			for conn.closes.Load() == 0 {
				select {
				case <-deadline:
					t.Fatal("untrusted certificate leaked PacketConn")
				case <-ticker.C:
				}
			}
			resolver.Close()
		})
	}
}

func TestDoH3RejectsNilPacketConn(t *testing.T) {
	config := &ResolverProto{Type: "https+h3", Addr: "https+h3://resolver.test/dns-query", Bootstrap: "127.0.0.1"}
	returned := make(chan struct{})
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		close(returned)
		return &xnet.PacketConnWrapper{}, nil
	}}
	resolver, err := NewDoH3Resolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	if err := resolver.Send(httpTestQuery(t, 1, "invalid-packet.example.")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("UDP dial did not start")
	}
	resolver.Close()
}
