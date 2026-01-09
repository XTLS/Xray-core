package hysteria2

import (
	"context"
	go_tls "crypto/tls"
	"encoding/binary"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria2/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria2/obfs"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type udpSessionManger struct {
	conn   *quic.Conn
	m      map[uint32]*InterUdpConn
	nextId uint32
	closed bool
	mutex  sync.RWMutex
}

func (m *udpSessionManger) run() {
	for {
		d, err := m.conn.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}

		if len(d) < 4 {
			continue
		}
		sessionId := binary.BigEndian.Uint32(d[:4])

		m.feed(sessionId, d)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.closed = true
	for _, udpConn := range m.m {
		m.close(udpConn)
	}
}

func (m *udpSessionManger) close(udpConn *InterUdpConn) {
	if !udpConn.closed {
		udpConn.closed = true
		close(udpConn.ch)
		delete(m.m, udpConn.id)
	}
}

func (m *udpSessionManger) udp() (*InterUdpConn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return nil, errors.New("closed")
	}

	udpConn := &InterUdpConn{
		conn:   m.conn,
		local:  m.conn.LocalAddr(),
		remote: m.conn.RemoteAddr(),

		id: m.nextId,
		ch: make(chan []byte, udpMessageChanSize),
	}
	udpConn.closeFunc = func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.close(udpConn)
	}
	m.m[m.nextId] = udpConn
	m.nextId++

	return udpConn, nil
}

func (m *udpSessionManger) feed(sessionId uint32, d []byte) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	udpConn, ok := m.m[sessionId]
	if !ok {
		return
	}

	select {
	case udpConn.ch <- d:
	default:
	}
}

type client struct {
	ctx          context.Context
	dest         net.Destination
	pktConn      net.PacketConn
	conn         *quic.Conn
	config       *Config
	tlsConfig    *go_tls.Config
	socketConfig *internet.SocketConfig
	closed       bool
	udpSM        *udpSessionManger
	mutex        sync.Mutex
}

func (c *client) status() Status {
	if c.conn == nil {
		return StatusUnknown
	}
	select {
	case <-c.conn.Context().Done():
		return StatusInactive
	default:
		return StatusActive
	}
}

func (c *client) close() {
	_ = c.conn.CloseWithError(closeErrCodeOK, "")
	_ = c.pktConn.Close()
}

func (c *client) dial() error {
	status := c.status()
	if status == StatusActive {
		return nil
	}
	if status == StatusInactive {
		c.close()
	}

	c.pktConn = nil
	c.conn = nil
	c.udpSM = nil

	raw, err := internet.DialSystem(c.ctx, c.dest, c.socketConfig)
	if err != nil {
		return errors.New("failed to dial to dest").Base(err)
	}

	pktConn, ok := raw.(net.PacketConn)
	if !ok {
		return errors.New("raw is not PacketConn")
	}

	if c.config.Obfs != "" {
		ob, err := obfs.NewSalamanderObfuscator([]byte(c.config.Obfs))
		if err != nil {
			return errors.New("obfs err").Base(err)
		}
		pktConn = obfs.WrapPacketConn(pktConn, ob)
	}

	var quicConn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: c.tlsConfig,
		QUICConfig: &quic.Config{
			InitialStreamReceiveWindow:     c.config.InitStreamReceiveWindow,
			MaxStreamReceiveWindow:         c.config.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: c.config.InitConnReceiveWindow,
			MaxConnectionReceiveWindow:     c.config.MaxConnReceiveWindow,
			MaxIdleTimeout:                 time.Duration(c.config.MaxIdleTimeout) * time.Second,
			KeepAlivePeriod:                time.Duration(c.config.KeepAlivePeriod) * time.Second,
			DisablePathMTUDiscovery:        c.config.DisablePathMtuDiscovery,
			EnableDatagrams:                true,
			MaxDatagramFrameSize:           MaxDatagramFrameSize,
			DisablePathManager:             true,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *go_tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := quic.DialEarly(ctx, pktConn, c.dest.RawNetAddr(), tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			quicConn = qc
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
			CommonHeaderCCRX:    []string{strconv.FormatUint(c.config.Down, 10)},
			CommonHeaderPadding: []string{authRequestPadding.String()},
		},
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if quicConn != nil {
			_ = quicConn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return errors.New("RoundTrip err").Base(err)
	}
	if resp.StatusCode != StatusAuthOK {
		_ = quicConn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		return errors.New("auth failed")
	}
	_ = resp.Body.Close()

	serverUdp, _ := strconv.ParseBool(resp.Header.Get(ResponseHeaderUDPEnabled))
	serverAuto := resp.Header.Get(CommonHeaderCCRX)
	serverDown, _ := strconv.ParseUint(serverAuto, 10, 64)

	if serverAuto == "auto" || (c.config.Up == 0 && serverDown == 0) {
		congestion.UseBBR(quicConn)
	} else {
		congestion.UseBrutal(quicConn, min(c.config.Up, serverDown))
	}

	c.pktConn = pktConn
	c.conn = quicConn
	if c.config.Udp && serverUdp {
		c.udpSM = &udpSessionManger{
			conn:   quicConn,
			m:      make(map[uint32]*InterUdpConn),
			nextId: 1,
		}
		go c.udpSM.run()
	}

	return nil
}

func (c *client) remove() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return true
	}

	status := c.status()
	if status != StatusActive {
		c.closed = true
		if status == StatusInactive {
			c.close()
		}
	}
	return c.closed
}

func (c *client) tcp() (stat.Connection, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil, errors.New("closed")
	}

	err := c.dial()
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
	}, nil
}

func (c *client) udp() (stat.Connection, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil, errors.New("closed")
	}

	err := c.dial()
	if err != nil {
		return nil, err
	}

	if c.udpSM == nil {
		return nil, errors.New("server does not support udp")
	}

	return c.udpSM.udp()
}

type clientManger struct {
	m     map[string]*client
	mutex sync.Mutex
}

func (m *clientManger) clean() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for key, c := range m.m {
		if c.remove() {
			delete(m.m, key)
		}
	}
}

var manger *clientManger

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	addr := dest.NetAddr()
	config := streamSettings.ProtocolSettings.(*Config)

	manger.mutex.Lock()
	c, ok := manger.m[addr]
	if !ok {
		dest.Network = net.Network_UDP
		c = &client{
			ctx:          ctx,
			dest:         dest,
			config:       config,
			tlsConfig:    tlsConfig.GetTLSConfig(),
			socketConfig: streamSettings.SocketSettings,
		}
		manger.m[addr] = c
	}
	manger.mutex.Unlock()

	outbounds := session.OutboundsFromContext(ctx)
	targetUdp := len(outbounds) > 0 && outbounds[len(outbounds)-1].Target.Network == net.Network_UDP

	if config.Udp && targetUdp {
		return c.udp()
	}
	return c.tcp()
}

func init() {
	manger = &clientManger{
		m: make(map[string]*client),
	}
	(&task.Periodic{
		Interval: 30 * time.Second,
		Execute: func() error {
			manger.clean()
			return nil
		},
	}).Start()
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
