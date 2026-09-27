package scenarios

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	transmasque "github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	masqueServerV4 = netip.MustParseAddr("10.13.0.1")
	masqueServerV6 = netip.MustParseAddr("fd13::1")
	masqueClientV4 = netip.MustParsePrefix("10.13.0.2/32")
	masqueClientV6 = netip.MustParsePrefix("fd13::2/128")
)

const (
	masqueEchoPort      = 7
	masqueAuthorization = "Basic dUBleGFtcGxlLmNvbTpw"
)

func startMasqueServer(t *testing.T, h2 bool) (net.Port, [32]byte) {
	dev, _, gstack, err := wireguard.CreateNetTUN([]netip.Addr{masqueServerV4, masqueServerV6}, nil, transmasque.MinPacketSize, false)
	common.Must(err)
	t.Cleanup(func() { dev.Close() })

	for _, addr := range []netip.Addr{masqueServerV4, masqueServerV6} {
		proto := ipv4.ProtocolNumber
		if addr.Is6() {
			proto = ipv6.ProtocolNumber
		}
		local := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: masqueEchoPort}
		l, err := gonet.ListenTCP(gstack, local, proto)
		common.Must(err)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					b := make([]byte, 2048)
					for {
						n, err := c.Read(b)
						if err != nil {
							return
						}
						if _, err := c.Write(xor(b[:n])); err != nil {
							return
						}
					}
				}()
			}
		}()
		u, err := gonet.DialUDP(gstack, &local, nil, proto)
		common.Must(err)
		go func() {
			b := make([]byte, 2048)
			for {
				n, addr, err := u.ReadFrom(b)
				if err != nil {
					return
				}
				u.WriteTo(xor(b[:n]), addr)
			}
		}()
	}

	var current atomic.Pointer[connectip.Conn]
	go func() {
		bufs := [][]byte{make([]byte, transmasque.MinPacketSize)}
		sizes := []int{0}
		for {
			if _, err := dev.Read(bufs, sizes, 0); err != nil {
				return
			}
			if conn := current.Load(); conn != nil {
				if icmp, _ := conn.WritePacket(bufs[0][:sizes[0]]); len(icmp) > 0 {
					go dev.Write([][]byte{icmp}, 0)
				}
			}
		}
	}()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != transmasque.DefaultPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != masqueAuthorization {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		req, err := connectip.ParseProxyRequest(r)
		if err != nil {
			var perr *connectip.ProxyRequestParseError
			if go_errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
			}
			return
		}
		conn, err := (&connectip.Proxy{}).Proxy(w, req)
		if err != nil {
			return
		}
		defer conn.Close()
		common.Must(conn.AssignAddresses([]netip.Prefix{masqueClientV4, masqueClientV6}))
		common.Must(conn.AdvertiseRoute([]connectip.IPRoute{
			{StartIP: netip.IPv4Unspecified(), EndIP: netip.AddrFrom4([4]byte{255, 255, 255, 255})},
			{StartIP: netip.IPv6Unspecified(), EndIP: netip.AddrFrom16([16]byte{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})},
		}))
		go func() {
			for {
				ar, err := conn.ReceiveAddressRequest(context.Background())
				if err != nil {
					return
				}
				assigned := make([]netip.Prefix, len(ar.Prefixes))
				for i, p := range ar.Prefixes {
					if p.Addr().Is4() {
						assigned[i] = masqueClientV4
					} else {
						assigned[i] = masqueClientV6
					}
				}
				ar.Respond(assigned, nil)
			}
		}()
		current.Store(conn)
		b := make([]byte, 2048)
		for {
			n, err := conn.ReadPacket(b)
			if err != nil {
				if go_errors.Is(err, io.ErrShortBuffer) {
					continue
				}
				return
			}
			dev.Write([][]byte{b[:n]}, 0)
		}
	}

	certificate, certHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	key := common.Must2(x509.ParsePKCS8PrivateKey(certificate.PrivateKey))
	tlsConfig := &gotls.Config{
		Certificates: []gotls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: key}},
		NextProtos:   []string{http3.NextProtoH3},
	}
	if h2 {
		tlsConfig.NextProtos = []string{http2.NextProtoTLS}
		ln := common.Must2(gotls.Listen("tcp", "127.0.0.1:0", tlsConfig))
		t.Cleanup(func() { ln.Close() })
		go serveHTTP2(ln, http.HandlerFunc(handler))
		return net.Port(ln.Addr().(*net.TCPAddr).Port), certHash
	}
	pktConn := common.Must2(net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()}))
	tr := &quic.Transport{Conn: pktConn}
	ln := common.Must2(tr.ListenEarly(tlsConfig, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350}))
	server := &http3.Server{Handler: http.HandlerFunc(handler), EnableDatagrams: true}
	go server.ServeListener(ln)
	t.Cleanup(func() {
		server.Close()
		ln.Close()
		tr.Close()
		pktConn.Close()
	})

	return net.Port(pktConn.LocalAddr().(*net.UDPAddr).Port), certHash
}

func serveHTTP2(ln net.Listener, handler http.Handler) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go serveHTTP2Conn(conn, handler)
	}
}

type http2ServerConn struct {
	mu   sync.Mutex
	fr   *http2.Framer
	hbuf bytes.Buffer
	henc *hpack.Encoder
}

func (c *http2ServerConn) write(f func(*http2.Framer) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return f(c.fr)
}

func (c *http2ServerConn) writeHeaders(streamID uint32, status int, header http.Header) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hbuf.Reset()
	c.henc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	for k, vv := range header {
		for _, v := range vv {
			c.henc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v})
		}
	}
	return c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: c.hbuf.Bytes(), EndHeaders: true})
}

func (c *http2ServerConn) writeData(streamID uint32, endStream bool, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		n := min(len(data), 16384)
		if err := c.fr.WriteData(streamID, endStream && n == len(data), data[:n]); err != nil {
			return err
		}
		if data = data[n:]; len(data) == 0 {
			return nil
		}
	}
}

func serveHTTP2Conn(conn net.Conn, handler http.Handler) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(br, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	sc := &http2ServerConn{fr: http2.NewFramer(conn, br)}
	sc.henc = hpack.NewEncoder(&sc.hbuf)
	sc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := sc.write(func(fr *http2.Framer) error {
		if err := fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30},
		); err != nil {
			return err
		}
		return fr.WriteWindowUpdate(0, 1<<30)
	}); err != nil {
		return
	}

	bodies := make(map[uint32]*io.PipeWriter)
	defer func() {
		for _, body := range bodies {
			body.Close()
		}
	}()
	for {
		f, err := sc.fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				err = sc.write((*http2.Framer).WriteSettingsAck)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				err = sc.write(func(fr *http2.Framer) error { return fr.WritePing(true, f.Data) })
			}
		case *http2.MetaHeadersFrame:
			u, err := url.ParseRequestURI(f.PseudoValue("path"))
			if err != nil {
				return
			}
			pr, pw := io.Pipe()
			bodies[f.StreamID] = pw
			req := &http.Request{
				Method:     f.PseudoValue("method"),
				URL:        u,
				Proto:      "HTTP/2.0",
				ProtoMajor: 2,
				Header:     http.Header{},
				Host:       f.PseudoValue("authority"),
				Body:       pr,
			}
			for _, hf := range f.RegularFields() {
				req.Header.Add(hf.Name, hf.Value)
			}
			if protocol := f.PseudoValue("protocol"); protocol != "" {
				req.Header.Set(":protocol", protocol)
			}
			streamID := f.StreamID
			w := &http2ResponseWriter{conn: sc, streamID: streamID, header: http.Header{}}
			go func() {
				handler.ServeHTTP(w, req)
				w.WriteHeader(http.StatusOK)
				sc.writeData(streamID, true, nil)
			}()
		case *http2.DataFrame:
			if body := bodies[f.StreamID]; body != nil {
				if _, err := body.Write(f.Data()); err != nil || f.StreamEnded() {
					body.Close()
					delete(bodies, f.StreamID)
				}
			}
		case *http2.RSTStreamFrame:
			if body := bodies[f.StreamID]; body != nil {
				body.CloseWithError(http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode})
				delete(bodies, f.StreamID)
			}
		}
		if err != nil {
			return
		}
	}
}

type http2ResponseWriter struct {
	conn        *http2ServerConn
	streamID    uint32
	header      http.Header
	wroteHeader bool
}

func (w *http2ResponseWriter) Header() http.Header { return w.header }

func (w *http2ResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.conn.writeHeaders(w.streamID, code, w.header)
	}
}

func (w *http2ResponseWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	if err := w.conn.writeData(w.streamID, false, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *http2ResponseWriter) Flush() {}

func TestMasque(t *testing.T) {
	testMasque(t, false)
}

func TestMasqueHTTP2(t *testing.T) {
	testMasque(t, true)
}

func masqueDokodemo(port net.Port, addr netip.Addr, network net.Network) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
			Listen:   net.NewIPOrDomain(net.LocalHostIP),
		}),
		ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
			RewriteAddress:  net.NewIPOrDomain(net.IPAddress(addr.AsSlice())),
			RewritePort:     masqueEchoPort,
			AllowedNetworks: []net.Network{network},
		}),
	}
}

func masqueStreamSettings(tlsConfig *tls.Config, config *transmasque.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName: "masque",
		TransportSettings: []*internet.TransportConfig{
			{
				ProtocolName: "masque",
				Settings:     serial.ToTypedMessage(config),
			},
		},
		SecurityType:     serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(tlsConfig)},
	}
}

func masqueClientTLS(certHash [32]byte, alpn ...string) *tls.Config {
	return &tls.Config{
		ServerName:           "localhost",
		PinnedPeerCertSha256: [][]byte{certHash[:]},
		NextProtocol:         alpn,
	}
}

func masqueOutbound(serverPort net.Port, certHash [32]byte, h2 bool, authorization string) *core.OutboundHandlerConfig {
	tlsConfig := masqueClientTLS(certHash)
	if h2 {
		tlsConfig.NextProtocol = []string{http2.NextProtoTLS}
	}
	return &core.OutboundHandlerConfig{
		ProxySettings: serial.ToTypedMessage(&masque.ClientConfig{
			Server: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.LocalHostIP),
				Port:    uint32(serverPort),
			},
		}),
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			StreamSettings: masqueStreamSettings(tlsConfig, &transmasque.Config{
				Path:    transmasque.DefaultPath,
				Headers: map[string]string{"Authorization": authorization},
			}),
		}),
	}
}

func masqueClientConfig(serverPort net.Port, certHash [32]byte, h2 bool, authorization string, tcpPort, tcp6Port, udpPort net.Port, v4, v6 netip.Addr) *core.Config {
	return &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			masqueDokodemo(tcpPort, v4, net.Network_TCP),
			masqueDokodemo(tcp6Port, v6, net.Network_TCP),
			masqueDokodemo(udpPort, v4, net.Network_UDP),
		},
		Outbound: []*core.OutboundHandlerConfig{
			masqueOutbound(serverPort, certHash, h2, authorization),
		},
	}
}

func testMasqueTraffic(t *testing.T, tcpPort, tcp6Port, udpPort net.Port) {
	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(tcpPort, 1024*1024, time.Second*20))
	}
	errg.Go(testTCPConn(tcp6Port, 1024*1024, time.Second*20))
	errg.Go(testUDPConn(udpPort, 1024, time.Second*5))
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

func testMasque(t *testing.T, h2 bool) {
	serverPort, certHash := startMasqueServer(t, h2)

	tcpPort := tcp.PickPort()
	tcp6Port := tcp.PickPort()
	udpPort := udp.PickPort()
	clientConfig := masqueClientConfig(serverPort, certHash, h2, masqueAuthorization, tcpPort, tcp6Port, udpPort, masqueServerV4, masqueServerV6)

	servers, err := InitializeServerConfigs(clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	testMasqueTraffic(t, tcpPort, tcp6Port, udpPort)
}

func masqueServerInbound(serverPort net.Port, certificate *tls.Certificate, alpn ...string) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
			Listen:   net.NewIPOrDomain(net.LocalHostIP),
			StreamSettings: masqueStreamSettings(&tls.Config{
				Certificate:  []*tls.Certificate{certificate},
				NextProtocol: alpn,
			}, &transmasque.Config{Path: transmasque.DefaultPath}),
		}),
		ProxySettings: serial.ToTypedMessage(&masque.ServerConfig{
			Users: []*protocol.User{{
				Email:   "u@example.com",
				Account: serial.ToTypedMessage(&masque.Account{Password: "p"}),
			}},
			Address: []string{"10.14.0.1/24", "fd14::1/64"},
		}),
	}
}

func masqueServerConfig(serverPort net.Port, certificate *tls.Certificate, h2 bool, tcpDest, udpDest net.Destination) *core.Config {
	var alpn []string
	if h2 {
		alpn = []string{http2.NextProtoTLS}
	}
	redirect := func(tag string, dest net.Destination) *core.OutboundHandlerConfig {
		return &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(dest.Address),
						Port:    uint32(dest.Port),
					},
				},
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}
	}
	return &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{Networks: []net.Network{net.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "tcp"}},
					{Networks: []net.Network{net.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "udp"}},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			masqueServerInbound(serverPort, certificate, alpn...),
		},
		Outbound: []*core.OutboundHandlerConfig{
			redirect("tcp", tcpDest),
			redirect("udp", udpDest),
		},
	}
}

func testMasqueServer(t *testing.T, h2 bool, authorization string) error {
	tcpServer := tcp.Server{MsgProcessor: xor}
	tcpDest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()
	udpServer := udp.Server{MsgProcessor: xor}
	udpDest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := udp.PickPort()
	if h2 {
		serverPort = tcp.PickPort()
	}
	tcpPort := tcp.PickPort()
	tcp6Port := tcp.PickPort()
	udpPort := udp.PickPort()
	servers, err := InitializeServerConfigs(
		masqueServerConfig(serverPort, tls.ParseCertificate(ct), h2, tcpDest, udpDest),
		masqueClientConfig(serverPort, ctHash, h2, authorization, tcpPort, tcp6Port, udpPort, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")),
	)
	common.Must(err)
	defer CloseAllServers(servers)

	if authorization != masqueAuthorization {
		return testTCPConn(tcpPort, 1024, time.Second*5)()
	}
	testMasqueTraffic(t, tcpPort, tcp6Port, udpPort)
	return nil
}

func TestMasqueServer(t *testing.T) {
	testMasqueServer(t, false, masqueAuthorization)
}

func TestMasqueServerHTTP2(t *testing.T) {
	testMasqueServer(t, true, masqueAuthorization)
}

func TestMasqueServerRejectsWrongPassword(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		if err := testMasqueServer(t, h2, "Basic dUBleGFtcGxlLmNvbTp3cm9uZw=="); err == nil {
			t.Errorf("a wrong password got through (h2: %v)", h2)
		}
	}
}

func masqueIPPacket(src, dst netip.Addr, payload []byte) []byte {
	if src.Is4() {
		p := make([]byte, 20, 20+len(payload))
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(20+len(payload)))
		p[8] = 64
		p[9] = 253
		copy(p[12:], src.AsSlice())
		copy(p[16:], dst.AsSlice())
		return append(p, payload...)
	}
	p := make([]byte, 40, 40+len(payload))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(len(payload)))
	p[6] = 253
	p[7] = 64
	copy(p[8:], src.AsSlice())
	copy(p[24:], dst.AsSlice())
	return append(p, payload...)
}

func masqueIPAddrs(p []byte) (src, dst netip.Addr) {
	if p[0]>>4 == 4 {
		return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
	}
	return netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
}

func TestMasqueServerClientToClient(t *testing.T) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := udp.PickPort()
	servers, err := InitializeServerConfigs(&core.Config{
		Inbound: []*core.InboundHandlerConfig{
			masqueServerInbound(serverPort, tls.ParseCertificate(ct), http3.NextProtoH3, http2.NextProtoTLS),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	})
	common.Must(err)
	defer CloseAllServers(servers)

	dial := func(alpn ...string) *transmasque.Conn {
		streamSettings, err := internet.ToMemoryStreamConfig(masqueStreamSettings(masqueClientTLS(ctHash, alpn...), &transmasque.Config{
			Path:    transmasque.DefaultPath,
			Headers: map[string]string{"Authorization": masqueAuthorization},
		}))
		common.Must(err)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := transmasque.Dial(ctx, net.TCPDestination(net.LocalHostIP, serverPort), streamSettings)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn.(*transmasque.Conn)
	}
	h3 := dial()
	h2 := dial(http2.NextProtoTLS)

	for _, c := range []struct{ from, to *transmasque.Conn }{{h3, h2}, {h2, h3}} {
		for i := range c.from.LocalAddrs() {
			src, dst := c.from.LocalAddrs()[i], c.to.LocalAddrs()[i]
			payload := make([]byte, 1000)
			rand.Read(payload)
			if _, err := c.from.Write(masqueIPPacket(src, dst, payload)); err != nil {
				t.Fatal(err)
			}
			received := make(chan []byte, 1)
			go func() {
				b := make([]byte, 2048)
				n, _ := c.to.Read(b)
				received <- b[:n]
			}()
			select {
			case p := <-received:
				gotSrc, gotDst := masqueIPAddrs(p)
				if gotSrc != src || gotDst != dst || !bytes.HasSuffix(p, payload) {
					t.Fatalf("unexpected packet from %s to %s: %x", gotSrc, gotDst, p)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no packet from %s to %s", src, dst)
			}
		}
	}
}
