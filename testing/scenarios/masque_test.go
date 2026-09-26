package scenarios

import (
	"bufio"
	"bytes"
	"context"
	gotls "crypto/tls"
	"crypto/x509"
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
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
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
	masqueAuthorization = "Basic dTpw"
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

func testMasque(t *testing.T, h2 bool) {
	serverPort, certHash := startMasqueServer(t, h2)

	tcpPort := tcp.PickPort()
	tcp6Port := tcp.PickPort()
	udpPort := udp.PickPort()
	dokodemoTo := func(port net.Port, addr netip.Addr, network net.Network) *core.InboundHandlerConfig {
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
	tlsConfig := &tls.Config{
		ServerName:           "localhost",
		PinnedPeerCertSha256: [][]byte{certHash[:]},
	}
	if h2 {
		tlsConfig.NextProtocol = []string{http2.NextProtoTLS}
	}
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			dokodemoTo(tcpPort, masqueServerV4, net.Network_TCP),
			dokodemoTo(tcp6Port, masqueServerV6, net.Network_TCP),
			dokodemoTo(udpPort, masqueServerV4, net.Network_UDP),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&masque.ClientConfig{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "masque",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "masque",
								Settings: serial.ToTypedMessage(&transmasque.Config{
									Path:    transmasque.DefaultPath,
									Headers: map[string]string{"Authorization": masqueAuthorization},
								}),
							},
						},
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(tlsConfig),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

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
