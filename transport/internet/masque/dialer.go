package masque

import (
	"context"
	"net/http"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

const (
	MinPacketSize     = 1280
	initialPacketSize = 1350
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}
	config := streamSettings.ProtocolSettings.(*Config)
	if usesHTTP2(tlsConfig) {
		return dialHTTP2(ctx, dest, streamSettings, tlsConfig, config)
	}
	dest.Network = net.Network_UDP

	gotlsConfig := tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	gotlsConfig.NextProtos = []string{http3.NextProtoH3}

	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		MaxIncomingStreams:             -1,
		InitialPacketSize:              initialPacketSize,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		EnableDatagrams:                true,
		DisablePathManager:             true,
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	if quicParams.KeepAlivePeriod == 0 {
		quicConfig.KeepAlivePeriod = net.QuicgoH3KeepAlivePeriod
	}

	var pktConn net.PacketConn
	var udpAddr net.Addr
	if streamSettings.FinalMask != nil {
		conn, err := streamSettings.FinalMask.DialUDP(ctx, dest)
		if err != nil {
			return nil, errors.New("failed to dial to dest").Base(err)
		}
		pktConn = conn.(*finalmask.PacketConnWrapper).PacketConn
		udpAddr = conn.RemoteAddr()
	} else {
		conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to dial to dest").Base(err)
		}
		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			pktConn = c.PacketConn
			udpAddr = c.RemoteAddr()
		case *cnc.Connection:
			pktConn = &internet.FakePacketConn{Conn: c}
			udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
		default:
			panic(reflect.TypeOf(c))
		}
	}

	tr := &quic.Transport{Conn: pktConn, DisableGSO: quicParams.DisableGSO}
	qconn, err := tr.Dial(ctx, udpAddr, gotlsConfig, quicConfig)
	if err != nil {
		tr.Close()
		pktConn.Close()
		return nil, err
	}
	context.AfterFunc(qconn.Context(), func() { tr.Close(); pktConn.Close() })

	switch quicParams.Congestion {
	case "reno":
	case "", "bbr", "brutal":
		congestion.UseBBR(qconn, bbr.Profile(quicParams.BbrProfile))
	case "force-brutal":
		congestion.UseBrutal(qconn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
	default:
		qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		return nil, errors.New("unknown congestion control: ", quicParams.Congestion)
	}

	cc := (&http3.Transport{EnableDatagrams: true, DisableCompression: true}).NewClientConn(qconn)
	conn, err := establish(ctx, connectip.NewClientConn(cc), quicConn{qconn}, func() {
		qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "")
	}, config, authority(config, gotlsConfig.ServerName, dest.Port))
	if err != nil {
		qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		return nil, err
	}
	return conn, nil
}

func usesHTTP2(config *tls.Config) bool {
	return slices.Contains(config.NextProtocol, http2.NextProtoTLS) && !slices.Contains(config.NextProtocol, http3.NextProtoH3)
}

func dialHTTP2(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, tlsConfig *tls.Config, config *Config) (stat.Connection, error) {
	dest.Network = net.Network_TCP
	gotlsConfig := tlsConfig.GetTLSConfig(tls.WithDestination(dest))

	var conn net.Conn
	var err error
	if streamSettings.FinalMask != nil {
		conn, err = streamSettings.FinalMask.DialTCP(ctx, dest)
	} else {
		conn, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	}
	if err != nil {
		return nil, errors.New("failed to dial to dest").Base(err)
	}
	if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
		conn = tls.UClient(conn, gotlsConfig, fingerprint)
	} else {
		conn = tls.Client(conn, gotlsConfig)
	}
	tlsConn := conn.(tls.Interface)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if protocol := tlsConn.NegotiatedProtocol(); protocol != http2.NextProtoTLS {
		conn.Close()
		return nil, errors.New("the server negotiated ", strconv.Quote(protocol), " instead of h2")
	}

	cc, err := newHTTP2ClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	mconn, err := establish(ctx, connectip.NewHTTP2ClientConn(cc), cc, func() { cc.Close() }, config, authority(config, gotlsConfig.ServerName, dest.Port))
	if err != nil {
		cc.Close()
		return nil, err
	}
	return mconn, nil
}

type tunnelClient interface {
	Dial(*connectip.Request) (*connectip.Conn, *http.Response, error)
}

func establish(ctx context.Context, client tunnelClient, hconn httpConn, abort func(), config *Config, host string) (*Conn, error) {
	stop := context.AfterFunc(ctx, abort)
	defer stop()

	req, err := connectip.NewRequest(ctx, "https://"+host+config.Path)
	if err != nil {
		return nil, err
	}
	header := req.Header()
	for k, v := range config.Headers {
		header.Set(k, v)
	}
	switch header.Get("User-Agent") {
	case "":
		header["User-Agent"] = nil
	case "chrome":
		header.Set("User-Agent", utils.ChromeUA)
	case "firefox":
		header.Set("User-Agent", utils.FirefoxUA)
	case "safari":
		header.Set("User-Agent", utils.SafariUA)
	case "edge":
		header.Set("User-Agent", utils.MSEdgeUA)
	case "curl":
		header.Set("User-Agent", utils.CurlUA)
	case "golang":
		header.Del("User-Agent")
	}

	ipConn, _, err := client.Dial(req)
	if err != nil {
		if ctx.Err() != nil {
			err = context.Cause(ctx)
		}
		return nil, errors.New("CONNECT-IP request failed").Base(err)
	}

	if n := ipConn.MaxPacketSize(); n < MinPacketSize {
		ipConn.Close()
		return nil, errors.New("the tunnel can only carry ", n, "-byte packets, less than ", MinPacketSize)
	}

	if _, err := ipConn.RequestAddresses([]netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 32),
		netip.PrefixFrom(netip.IPv6Unspecified(), 128),
	}); err != nil {
		ipConn.Close()
		return nil, err
	}
	var local []netip.Addr
	for len(local) == 0 {
		assigned, err := ipConn.ReceiveAddressAssignment(ctx)
		if err != nil {
			ipConn.Close()
			return nil, errors.New("no address assigned").Base(err)
		}
		local = localAddrs(assigned)
	}
	if !stop() {
		ipConn.Close()
		return nil, errors.New("no address assigned").Base(context.Cause(ctx))
	}

	conn := &Conn{
		ipConn:   ipConn,
		httpConn: hconn,
		local:    local,
	}
	go conn.serveAddressAssignments()
	go conn.serveAddressRequests()
	return conn, nil
}

func localAddrs(assigned []connectip.AssignedAddress) []netip.Addr {
	var local []netip.Addr
	var has4, has6 bool
	for _, a := range assigned {
		if a.Rejected() {
			continue
		}
		addr := a.IPPrefix.Addr()
		if a.IPPrefix.Bits() != addr.BitLen() {
			addr = a.IPPrefix.Masked().Addr().Next()
		}
		if addr.Is4() && !has4 {
			has4 = true
			local = append(local, addr)
		} else if addr.Is6() && !has6 {
			has6 = true
			local = append(local, addr)
		}
	}
	return local
}

func authority(config *Config, serverName string, port net.Port) string {
	if config.Host != "" {
		return config.Host
	}
	host := strings.TrimSuffix(strings.TrimPrefix(serverName, "["), "]")
	if port == 443 {
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port.String())
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
