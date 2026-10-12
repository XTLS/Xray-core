package xdns

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func startDoH3VirtualTestGateway(t *testing.T, handler http.Handler) (string, *ResolverProto, *finalmask.Dialer) {
	t.Helper()
	endpoint, config, _ := startDoH3TestGateway(t, handler)
	u, err := url.Parse(endpoint)
	if err != nil { t.Fatal(err) }
	peer := net.JoinHostPort(config.Bootstrap, u.Port())
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination)(net.Conn,error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "udp", peer)
		if err != nil { return nil, err }
		virtual := cnc.NewConnection(
			cnc.ConnectionInput(raw),
			cnc.ConnectionOutputMultiUDP(buf.NewPacketReader(raw)),
			cnc.ConnectionOnClose(raw),
		)
		return &xnet.PacketConnWrapper{PacketConn: &internet.FakePacketConn{Conn: virtual}, Dest: &net.UDPAddr{IP: net.IPv4zero}}, nil
	}}
	return endpoint, config, dialer
}

func TestDoH3VirtualPeerWireAndClose(t *testing.T) {
	_, config, dialer := startDoH3VirtualTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.TLS.NegotiatedProtocol != "h3" || r.TLS.ServerName != "resolver.test" { t.Error("virtual route lost H3 or authenticated origin") }
		body, err := io.ReadAll(r.Body)
		if err != nil { t.Error(err); return }
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(httpTestResponse(t, body))
	}))
	closed := make(chan struct{})
	dial := dialer.DialUDPContext
	dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination)(net.Conn,error) {
		conn, err := dial(ctx, dest)
		if err != nil { return nil, err }
		wrapper := conn.(*xnet.PacketConnWrapper)
		packet := wrapper.PacketConn.(*internet.FakePacketConn)
		packet.Conn = &httpTestTrackedConn{Conn: packet.Conn, closed: closed}
		return wrapper, nil
	}
	resolver, err := NewDoH3Resolver(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	query := httpTestQuery(t, 31, "virtual-peer.example.")
	if err := resolver.Send(query); err != nil { t.Fatal(err) }
	if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, query)) { t.Fatal("virtual peer changed raw DNS response") }
	resolver.Close()
	resolver.Close()
	select { case <-closed: case <-time.After(time.Second): t.Fatal("Close left virtual packet route open") }
}

func TestDoH3VirtualPeerCloseCancelsBody(t *testing.T) {
	testHTTPResolverClose(t, NewDoH3Resolver, startDoH3VirtualTestGateway)
}

func TestDoH3RealPacketConnRejectsZeroPeer(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = packet.Close() })
	closed := make(chan struct{})
	tracked := &httpTestTrackedPacketConn{PacketConn: packet, closed: closed}
	dialer := &finalmask.Dialer{DialUDPContext: func(context.Context, xnet.Destination)(net.Conn,error) {
		return &xnet.PacketConnWrapper{PacketConn: tracked, Dest: &net.UDPAddr{IP: net.IPv4zero}}, nil
	}}
	resolver, err := NewDoH3Resolver(&ResolverProto{Type: "https+h3", Addr: "https://resolver.test/dns-query", Bootstrap: "127.0.0.1"}, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	if err := resolver.Send(httpTestQuery(t, 1, "bad-peer.example.")); err != nil { t.Fatal(err) }
	select { case <-closed: case <-time.After(time.Second): t.Fatal("ordinary UDP zero peer was accepted") }
}
