package splithttp

import (
	"context"
	gotls "crypto/tls"
	"expvar"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/udphop"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const masqueTelemetryUnscopedKey = "_unscoped"

type masqueTelemetry struct {
	requestedSessions             atomic.Int64
	datagramReadEnabledSessions   atomic.Int64
	datagramWriteEnabledSessions  atomic.Int64
	bidirectionalDatagramSessions atomic.Int64
	readFallbackSessions          atomic.Int64
	writeFallbackSessions         atomic.Int64
	streamReadOps                 atomic.Int64
	streamReadBytes               atomic.Int64
	streamWriteOps                atomic.Int64
	streamWriteBytes              atomic.Int64
	datagramReadPackets           atomic.Int64
	datagramReadBytes             atomic.Int64
	datagramWritePackets          atomic.Int64
	datagramWriteBytes            atomic.Int64
}

func (t *masqueTelemetry) snapshot() map[string]int64 {
	return map[string]int64{
		"requested_sessions":              t.requestedSessions.Load(),
		"datagram_read_enabled_sessions":  t.datagramReadEnabledSessions.Load(),
		"datagram_write_enabled_sessions": t.datagramWriteEnabledSessions.Load(),
		"bidirectional_datagram_sessions": t.bidirectionalDatagramSessions.Load(),
		"read_fallback_sessions":          t.readFallbackSessions.Load(),
		"write_fallback_sessions":         t.writeFallbackSessions.Load(),
		"stream_read_ops":                 t.streamReadOps.Load(),
		"stream_read_bytes":               t.streamReadBytes.Load(),
		"stream_write_ops":                t.streamWriteOps.Load(),
		"stream_write_bytes":              t.streamWriteBytes.Load(),
		"datagram_read_packets":           t.datagramReadPackets.Load(),
		"datagram_read_bytes":             t.datagramReadBytes.Load(),
		"datagram_write_packets":          t.datagramWritePackets.Load(),
		"datagram_write_bytes":            t.datagramWriteBytes.Load(),
	}
}

type masqueTelemetryScope struct {
	global   *masqueTelemetry
	outbound *masqueTelemetry
}

func (s masqueTelemetryScope) apply(fn func(*masqueTelemetry)) {
	if s.global != nil {
		fn(s.global)
	}
	if s.outbound != nil {
		fn(s.outbound)
	}
}

type masqueTelemetryRegistry struct {
	global   masqueTelemetry
	outbound sync.Map // map[string]*masqueTelemetry
}

func (r *masqueTelemetryRegistry) scope(outboundKey string) masqueTelemetryScope {
	scope := masqueTelemetryScope{global: &r.global}
	if outboundKey == "" {
		outboundKey = masqueTelemetryUnscopedKey
	}
	scope.outbound = r.outboundTelemetry(outboundKey)
	return scope
}

func (r *masqueTelemetryRegistry) outboundTelemetry(outboundKey string) *masqueTelemetry {
	if outboundKey == "" {
		outboundKey = masqueTelemetryUnscopedKey
	}
	if existing, ok := r.outbound.Load(outboundKey); ok {
		return existing.(*masqueTelemetry)
	}
	created := new(masqueTelemetry)
	actual, _ := r.outbound.LoadOrStore(outboundKey, created)
	return actual.(*masqueTelemetry)
}

func (r *masqueTelemetryRegistry) globalSnapshot() map[string]int64 {
	return r.global.snapshot()
}

func (r *masqueTelemetryRegistry) outboundSnapshot() map[string]map[string]int64 {
	resp := map[string]map[string]int64{}
	r.outbound.Range(func(key, value any) bool {
		resp[key.(string)] = value.(*masqueTelemetry).snapshot()
		return true
	})
	return resp
}

func (r *masqueTelemetryRegistry) outboundSnapshotFor(outboundKey string) map[string]int64 {
	if outboundKey == "" {
		outboundKey = masqueTelemetryUnscopedKey
	}
	if value, ok := r.outbound.Load(outboundKey); ok {
		return value.(*masqueTelemetry).snapshot()
	}
	return (&masqueTelemetry{}).snapshot()
}

func (r *masqueTelemetryRegistry) snapshot() map[string]interface{} {
	return map[string]interface{}{
		"global":   r.globalSnapshot(),
		"outbound": r.outboundSnapshot(),
	}
}

var globalMASQUETelemetry masqueTelemetryRegistry

func masqueTelemetryOutboundKeyFromContext(ctx context.Context) string {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return masqueTelemetryUnscopedKey
	}
	ob := outbounds[len(outbounds)-1]
	switch {
	case ob.Tag != "":
		return ob.Tag
	case ob.Name != "":
		return "name:" + ob.Name
	default:
		return masqueTelemetryUnscopedKey
	}
}

func init() {
	expvar.Publish("masque", expvar.Func(func() interface{} {
		return globalMASQUETelemetry.snapshot()
	}))
}

type masqueStream interface {
	io.ReadWriteCloser
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Context() context.Context
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type masqueConn struct {
	stream     masqueStream
	localAddr  net.Addr
	remoteAddr net.Addr
	closeFunc  func() error

	readMu         sync.Mutex
	writeMu        sync.Mutex
	stateMu        sync.RWMutex
	readDatagrams  bool
	writeDatagrams bool
	readBuf        []byte
	readPos        int
	closeOnce      sync.Once

	requestedDatagrams          bool
	readEnabledCounted          bool
	writeEnabledCounted         bool
	bidirectionalEnabledCounted bool
	telemetry                   masqueTelemetryScope
}

func (c *masqueConn) EnableTransportDatagramRead() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !c.readDatagrams {
		c.readDatagrams = true
		c.readBuf = nil
		c.readPos = 0
		if !c.readEnabledCounted {
			c.telemetry.apply(func(t *masqueTelemetry) {
				t.datagramReadEnabledSessions.Add(1)
			})
			c.readEnabledCounted = true
		}
		c.maybeCountBidirectionalLocked()
	}
	return nil
}

func (c *masqueConn) EnableTransportDatagramWrite() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !c.writeDatagrams {
		c.writeDatagrams = true
		if !c.writeEnabledCounted {
			c.telemetry.apply(func(t *masqueTelemetry) {
				t.datagramWriteEnabledSessions.Add(1)
			})
			c.writeEnabledCounted = true
		}
		c.maybeCountBidirectionalLocked()
	}
	return nil
}

func (c *masqueConn) maybeCountBidirectionalLocked() {
	if c.readDatagrams && c.writeDatagrams && !c.bidirectionalEnabledCounted {
		c.telemetry.apply(func(t *masqueTelemetry) {
			t.bidirectionalDatagramSessions.Add(1)
		})
		c.bidirectionalEnabledCounted = true
	}
}

func (c *masqueConn) Read(p []byte) (int, error) {
	c.stateMu.RLock()
	readDatagrams := c.readDatagrams
	c.stateMu.RUnlock()
	if !readDatagrams {
		n, err := c.stream.Read(p)
		if n > 0 {
			c.telemetry.apply(func(t *masqueTelemetry) {
				t.streamReadOps.Add(1)
				t.streamReadBytes.Add(int64(n))
			})
		}
		return n, err
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readPos >= len(c.readBuf) {
		ctx := c.stream.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		data, err := c.stream.ReceiveDatagram(ctx)
		if err != nil {
			return 0, err
		}
		c.telemetry.apply(func(t *masqueTelemetry) {
			t.datagramReadPackets.Add(1)
			t.datagramReadBytes.Add(int64(len(data)))
		})
		c.readBuf = data
		c.readPos = 0
	}

	n := copy(p, c.readBuf[c.readPos:])
	c.readPos += n
	if c.readPos >= len(c.readBuf) {
		c.readBuf = nil
		c.readPos = 0
	}
	return n, nil
}

func (c *masqueConn) Write(p []byte) (int, error) {
	c.stateMu.RLock()
	writeDatagrams := c.writeDatagrams
	c.stateMu.RUnlock()
	if !writeDatagrams {
		n, err := c.stream.Write(p)
		if n > 0 {
			c.telemetry.apply(func(t *masqueTelemetry) {
				t.streamWriteOps.Add(1)
				t.streamWriteBytes.Add(int64(n))
			})
		}
		return n, err
	}
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.stream.SendDatagram(p); err != nil {
		return 0, err
	}
	c.telemetry.apply(func(t *masqueTelemetry) {
		t.datagramWritePackets.Add(1)
		t.datagramWriteBytes.Add(int64(len(p)))
	})
	return len(p), nil
}

func (c *masqueConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.stateMu.RLock()
		requestedDatagrams := c.requestedDatagrams
		readDatagrams := c.readDatagrams
		writeDatagrams := c.writeDatagrams
		c.stateMu.RUnlock()
		if requestedDatagrams {
			if !readDatagrams {
				c.telemetry.apply(func(t *masqueTelemetry) {
					t.readFallbackSessions.Add(1)
				})
			}
			if !writeDatagrams {
				c.telemetry.apply(func(t *masqueTelemetry) {
					t.writeFallbackSessions.Add(1)
				})
			}
		}
		if c.closeFunc != nil {
			err = c.closeFunc()
			return
		}
		err = c.stream.Close()
	})
	return err
}

func (c *masqueConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *masqueConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *masqueConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *masqueConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *masqueConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func newMASQUEConn(stream masqueStream, localAddr, remoteAddr net.Addr, closeFunc func() error, requestedDatagrams bool, telemetry masqueTelemetryScope) *masqueConn {
	conn := &masqueConn{
		stream:             stream,
		localAddr:          localAddr,
		remoteAddr:         remoteAddr,
		closeFunc:          closeFunc,
		requestedDatagrams: requestedDatagrams,
		telemetry:          telemetry,
	}
	if requestedDatagrams {
		conn.telemetry.apply(func(t *masqueTelemetry) {
			t.requestedSessions.Add(1)
		})
	}
	return conn
}

func newH3QUICConfig(streamSettings *internet.MemoryStreamConfig, keepAlivePeriod time.Duration, enableDatagrams bool) *quic.Config {
	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		MaxIncomingStreams:             quicParams.MaxIncomingStreams,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery,
		EnableDatagrams:                enableDatagrams,
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = net.ConnIdleTimeout
	}
	if quicParams.KeepAlivePeriod == 0 && keepAlivePeriod == 0 {
		quicConfig.KeepAlivePeriod = net.QuicgoH3KeepAlivePeriod
	}
	if quicParams.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = -1
	}
	return quicConfig
}

func dialQUICConn(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, tlsCfg *gotls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{}
	}
	if quicParams.UdpHop == nil {
		quicParams.UdpHop = &internet.UdpHop{}
	}

	udphopDialer := func(addr *net.UDPAddr) (net.PacketConn, error) {
		conn, err := internet.DialSystem(ctx, net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), streamSettings.SocketSettings)
		if err != nil {
			errors.LogDebug(context.Background(), "skip hop: failed to dial to dest")
			return nil, errors.New().Base(err)
		}

		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			return c.PacketConn, nil
		case *net.UDPConn:
			return c, nil
		default:
			errors.LogDebug(context.Background(), "skip hop: udphop requires being at the outermost level ", reflect.TypeOf(c))
			conn.Close()
			return nil, errors.New()
		}
	}

	var index int
	if len(quicParams.UdpHop.Ports) > 0 {
		index = rand.Intn(len(quicParams.UdpHop.Ports))
		dest.Port = net.Port(quicParams.UdpHop.Ports[index])
	}

	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	var udpConn net.PacketConn
	var udpAddr *net.UDPAddr

	switch c := conn.(type) {
	case *internet.PacketConnWrapper:
		udpConn = c.PacketConn
		udpAddr, err = net.ResolveUDPAddr("udp", c.Dest.String())
		if err != nil {
			conn.Close()
			return nil, err
		}
	case *net.UDPConn:
		udpConn = c
		udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
		if err != nil {
			conn.Close()
			return nil, err
		}
	default:
		udpConn = &internet.FakePacketConn{Conn: c}
		udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
		if err != nil {
			conn.Close()
			return nil, err
		}

		if len(quicParams.UdpHop.Ports) > 0 {
			conn.Close()
			return nil, errors.New("udphop requires being at the outermost level ", reflect.TypeOf(c))
		}
	}

	if len(quicParams.UdpHop.Ports) > 0 {
		addr := &udphop.UDPHopAddr{
			IP:    udpAddr.IP,
			Ports: quicParams.UdpHop.Ports,
		}
		udpConn, err = udphop.NewUDPHopPacketConn(addr, index, quicParams.UdpHop.IntervalMin, quicParams.UdpHop.IntervalMax, udphopDialer, udpConn)
		if err != nil {
			conn.Close()
			return nil, errors.New("udphop err").Base(err)
		}
	}

	if streamSettings.UdpmaskManager != nil {
		udpConn, err = streamSettings.UdpmaskManager.WrapPacketConnClient(udpConn)
		if err != nil {
			conn.Close()
			return nil, errors.New("mask err").Base(err)
		}
	}

	quicConn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, quicConfig)
	if err != nil {
		return nil, err
	}

	switch quicParams.Congestion {
	case "force-brutal":
		errors.LogDebug(context.Background(), quicConn.RemoteAddr(), " ", "congestion brutal bytes per second ", quicParams.BrutalUp)
		congestion.UseBrutal(quicConn, quicParams.BrutalUp)
	case "reno":
		errors.LogDebug(context.Background(), quicConn.RemoteAddr(), " ", "congestion reno")
	default:
		errors.LogDebug(context.Background(), quicConn.RemoteAddr(), " ", "congestion bbr")
		congestion.UseBBR(quicConn)
	}

	return quicConn, nil
}

func dialMASQUE(ctx context.Context, dest net.Destination, requestURL url.URL, streamSettings *internet.MemoryStreamConfig, tlsCfg *gotls.Config) (stat.Connection, error) {
	transportConfig := streamSettings.ProtocolSettings.(*Config)
	quicConfig := newH3QUICConfig(streamSettings, 0, true)
	quicConn, err := dialQUICConn(ctx, dest, streamSettings, tlsCfg, quicConfig)
	if err != nil {
		return nil, err
	}

	clientConn := (&http3.Transport{
		EnableDatagrams: true,
		QUICConfig:      quicConfig,
	}).NewClientConn(quicConn)

	select {
	case <-quicConn.HandshakeComplete():
	case <-ctx.Done():
		_ = quicConn.CloseWithError(0, "")
		return nil, context.Cause(ctx)
	}

	select {
	case <-clientConn.ReceivedSettings():
	case <-ctx.Done():
		_ = quicConn.CloseWithError(0, "")
		return nil, context.Cause(ctx)
	}

	if !clientConn.Settings().EnableExtendedConnect {
		_ = quicConn.CloseWithError(0, "")
		return nil, errors.New("http3: server didn't enable Extended CONNECT")
	}

	reqStream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodConnect, requestURL.String(), nil)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, err
	}
	req.Host = requestURL.Host
	transportConfig.FillStreamRequest(req, "", "")

	if err := reqStream.SendRequestHeader(req); err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, err
	}
	resp, err := reqStream.ReadResponse()
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = quicConn.CloseWithError(0, "")
		return nil, errors.New("unexpected MASQUE status ", resp.StatusCode)
	}

	return newMASQUEConn(reqStream, quicConn.LocalAddr(), quicConn.RemoteAddr(), func() error {
		reqStream.CancelRead(0)
		reqStream.CancelWrite(0)
		_ = reqStream.Close()
		return quicConn.CloseWithError(0, "")
	}, true, globalMASQUETelemetry.scope(masqueTelemetryOutboundKeyFromContext(ctx))), nil
}

func newServerMASQUEConn(stream *http3.Stream, localAddr, remoteAddr net.Addr) stat.Connection {
	return newMASQUEConn(stream, localAddr, remoteAddr, func() error {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return stream.Close()
	}, true, globalMASQUETelemetry.scope(masqueTelemetryUnscopedKey))
}

func unexpectedMASQUEStatusError(code int) error {
	return errors.New(fmt.Sprintf("unexpected MASQUE status %d", code))
}
