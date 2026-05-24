package hysteria

import (
	"context"
	go_tls "crypto/tls"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/hysteria/udphop"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type client struct {
	sync.Mutex

	dest           net.Destination
	config         *Config
	tlsConfig      *go_tls.Config
	socketConfig   *internet.SocketConfig
	udpmaskManager *finalmask.UdpmaskManager
	quicParams     *internet.QuicParams

	conn    *quic.Conn
	tr      *quic.Transport
	pktConn net.PacketConn
	udpSM   *udpSessionManager
}

func (c *client) status() status {
	if c.conn == nil {
		return StatusNull
	}
	select {
	case <-c.conn.Context().Done():
		return StatusInactive
	default:
		return StatusActive
	}
}

func (c *client) close() {
	c.conn.CloseWithError(closeErrCodeOK, "")
	c.tr.Close()
	c.pktConn.Close()
	c.conn = nil
	c.tr = nil
	c.pktConn = nil
	c.udpSM = nil
}

func (c *client) dial(ctx context.Context) error {
	status := c.status()
	if status == StatusActive {
		return nil
	}
	if status == StatusInactive {
		c.close()
	}

	quicParams := c.quicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
			UdpHop:     &internet.UdpHop{},
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           MaxDatagramFrameSize,
		OmitMaxDatagramFrameSize:       time.Now().After(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)),
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = 8388608
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = 8388608
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	// if quicParams.KeepAlivePeriod == 0 {
	// 	quicConfig.KeepAlivePeriod = 10 * time.Second
	// }

	udpHopDialer := func(addr *net.UDPAddr) (net.PacketConn, error) {
		conn, err := internet.DialSystem(ctx, net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), c.socketConfig)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "skip hop: failed to dial to dest")
			return nil, errors.New("")
		}

		var pktConn net.PacketConn

		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			pktConn = c.PacketConn
		default:
			panic(reflect.TypeOf(c))
		}

		return pktConn, nil
	}

	var pktConn net.PacketConn
	var udpAddr *net.UDPAddr
	if len(quicParams.UdpHop.Ports) > 0 {
		index := rand.Intn(len(quicParams.UdpHop.Ports))
		c.dest.Port = net.Port(quicParams.UdpHop.Ports[index])
		conn, err := internet.DialSystem(ctx, c.dest, c.socketConfig)
		if err != nil {
			return errors.New("failed to dial to dest").Base(err)
		}
		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			pktConn = c.PacketConn
			udpAddr = conn.RemoteAddr().(*net.UDPAddr)
		default:
			panic(reflect.TypeOf(c))
		}
		pktConn = udphop.NewUDPHopPacketConn(udphop.ToAddrs(udpAddr.IP, quicParams.UdpHop.Ports), time.Duration(quicParams.UdpHop.IntervalMin)*time.Second, time.Duration(quicParams.UdpHop.IntervalMax)*time.Second, udpHopDialer, pktConn, index)
	} else {
		conn, err := internet.DialSystem(ctx, c.dest, c.socketConfig)
		if err != nil {
			return errors.New("failed to dial to dest").Base(err)
		}
		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			pktConn = c.PacketConn
			udpAddr = c.RemoteAddr().(*net.UDPAddr)
		case *cnc.Connection:
			pktConn = &internet.FakePacketConn{Conn: c}
			udpAddr = &net.UDPAddr{IP: c.RemoteAddr().(*net.TCPAddr).IP, Port: c.RemoteAddr().(*net.TCPAddr).Port}
		default:
			panic(reflect.TypeOf(c))
		}
	}

	if c.udpmaskManager != nil {
		newConn, err := c.udpmaskManager.WrapPacketConnClient(pktConn)
		if err != nil {
			pktConn.Close()
			return errors.New("mask err").Base(err)
		}
		pktConn = newConn
	}

	tr := &quic.Transport{Conn: pktConn}

	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: c.tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *go_tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   URLHost,
			Path:   URLPath,
		},
		Header: http.Header{
			RequestHeaderAuth:   []string{c.config.Auth},
			CommonHeaderCCRX:    []string{strconv.FormatUint(quicParams.BrutalDown, 10)},
			CommonHeaderPadding: []string{AuthRequestPadding.String()},
		},
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = tr.Close()
		_ = pktConn.Close()
		return err
	}
	if resp.StatusCode != StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = tr.Close()
		_ = pktConn.Close()
		return errors.New("auth failed code ", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// udp, _ := strconv.ParseBool(resp.Header.Get(ResponseHeaderUDPEnabled))
	down, _ := strconv.ParseUint(resp.Header.Get(CommonHeaderCCRX), 10, 64)

	switch quicParams.Congestion {
	case "reno":
	case "bbr":
		congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
	case "", "brutal":
		if quicParams.BrutalUp == 0 || down == 0 {
			congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
		} else {
			congestion.UseBrutal(conn, min(quicParams.BrutalUp, down))
		}
	case "force-brutal":
		congestion.UseBrutal(conn, quicParams.BrutalUp)
	default:
		panic(quicParams.Congestion)
	}

	c.pktConn = pktConn
	c.tr = tr
	c.conn = conn
	c.udpSM = &udpSessionManager{
		conn: conn,
		m:    make(map[uint32]*InterConn),
		next: 1,
	}
	go c.udpSM.run()

	return nil
}

func (c *client) tcp(ctx context.Context) (stat.Connection, error) {
	c.Lock()
	defer c.Unlock()

	err := c.dial(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return &interConn{
		stream: stream,
		local:  c.conn.LocalAddr(),
		remote: c.conn.RemoteAddr(),

		client: true,
	}, nil
}

func (c *client) udp(ctx context.Context) (stat.Connection, error) {
	c.Lock()
	defer c.Unlock()

	err := c.dial(ctx)
	if err != nil {
		return nil, err
	}

	return c.udpSM.udp()
}

func (c *client) clean() {
	c.Lock()
	if c.status() == StatusInactive {
		c.close()
	}
	c.Unlock()
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

type clientManager struct {
	sync.RWMutex
	m map[dialerConf]*client
}

func (m *clientManager) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	for range ticker.C {
		m.RLock()
		for _, c := range m.m {
			c.clean()
		}
		m.RUnlock()
	}
}

var manager *clientManager
var initmanager sync.Once

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	datagram := DatagramFromContext(ctx)
	dest.Network = net.Network_UDP

	initmanager.Do(func() {
		manager = &clientManager{
			m: make(map[dialerConf]*client),
		}
		go manager.clean()
	})

	manager.RLock()
	c := manager.m[dialerConf{dest, streamSettings}]
	manager.RUnlock()

	if c == nil {
		manager.Lock()
		c = manager.m[dialerConf{dest, streamSettings}]
		if c == nil {
			c = &client{
				dest:           dest,
				config:         streamSettings.ProtocolSettings.(*Config),
				tlsConfig:      tlsConfig.GetTLSConfig(),
				socketConfig:   streamSettings.SocketSettings,
				udpmaskManager: streamSettings.UdpmaskManager,
				quicParams:     streamSettings.QuicParams,
			}
			manager.m[dialerConf{dest, streamSettings}] = c
		}
		manager.Unlock()
	}

	if datagram {
		return c.udp(ctx)
	}
	return c.tcp(ctx)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
