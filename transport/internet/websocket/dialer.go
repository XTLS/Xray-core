package websocket

import (
	"context"
	gotls "crypto/tls"
	_ "embed"
	"encoding/base64"
	"io"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Dial dials a WebSocket connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)
	var conn net.Conn
	if streamSettings.ProtocolSettings.(*Config).Ed > 0 {
		ctx, cancel := context.WithCancel(ctx)
		conn = &delayDialConn{
			dialed:         make(chan bool, 1),
			cancel:         cancel,
			ctx:            ctx,
			dest:           dest,
			streamSettings: streamSettings,
		}
	} else {
		var err error
		if conn, err = dialWebSocket(ctx, dest, streamSettings, nil); err != nil {
			return nil, errors.New("failed to dial WebSocket").Base(err)
		}
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return internet.DialTCPWithHandshake(ctx, dest, streamSettings, nil)
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	tConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tConfig != nil {
		protocol = "wss"
		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		dialer.TLSClientConfig = tlsConfig
		fingerprint := tls.GetFingerprint(tConfig.Fingerprint)
		sockopt := streamSettings.SocketSettings
		raceHandshake := sockopt != nil && sockopt.HappyEyeballs != nil && sockopt.HappyEyeballs.SuccessDefinition == internet.HappyEyeballsConfig_TlsHandshakeComplete
		handshake := func(ctx context.Context, pconn net.Conn) (net.Conn, error) {
			if fingerprint == nil {
				// The same handshake as the websocket package does by itself
				cn := gotls.Client(pconn, tlsConfig)
				if err := cn.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						return nil, err
					}
				}
				return cn, nil
			}

			// TLS and apply the handshake
			cn := tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
			if err := cn.WebsocketHandshakeContext(ctx); err != nil {
				return nil, err
			}
			if !tlsConfig.InsecureSkipVerify {
				if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
					return nil, err
				}
			}
			return cn, nil
		}
		// Without uTLS the websocket package does the handshake by itself, unless
		// Happy Eyeballs has to race it.
		if fingerprint != nil || raceHandshake {
			dialer.NetDialTLSContext = func(dialCtx context.Context, _, addr string) (net.Conn, error) {
				handshakeCtx := ctx
				if fingerprint == nil {
					// The websocket package bounds its own handshake by HandshakeTimeout
					handshakeCtx = dialCtx
				}
				conn, err := internet.DialTCPWithHandshake(handshakeCtx, dest, streamSettings, handshake)
				if err != nil {
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}
				return conn, nil
			}
		}
	}

	if browser_dialer.HasBrowserDialer() {
		// For Browser Dialer's optimized IP and non-standard port
		host := wsSettings.Host
		if host == "" && tConfig.ServerName != "" {
			host = tConfig.ServerName
		}
		if host == "" {
			host = dest.Address.String()
		}
		if !(protocol == "ws" && dest.Port == 80) && !(protocol == "wss" && dest.Port == 443) {
			host += ":" + dest.Port.String()
		}
		uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

		conn, err := browser_dialer.DialWS(uri, ed)
		if err != nil {
			return nil, err
		}

		return NewConnection(conn, conn.RemoteAddr(), nil, wsSettings.HeartbeatPeriod), nil
	}

	host := dest.Address.String()
	if !(protocol == "ws" && dest.Port == 80) && !(protocol == "wss" && dest.Port == 443) {
		host += ":" + dest.Port.String()
	}
	uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

	header := wsSettings.GetRequestHeader()
	// See dialer.DialContext()
	header.Set("Host", wsSettings.Host)
	if header.Get("Host") == "" && tConfig != nil {
		header.Set("Host", tConfig.ServerName)
	}
	if header.Get("Host") == "" {
		header.Set("Host", dest.Address.String())
	}
	if ed != nil {
		// RawURLEncoding is support by both V2Ray/V2Fly and XRay.
		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	conn, resp, err := dialer.DialContext(ctx, uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, errors.New("failed to dial to (", uri, "): ", reason).Base(err)
	}

	return NewConnection(conn, conn.RemoteAddr(), nil, wsSettings.HeartbeatPeriod), nil
}

type delayDialConn struct {
	net.Conn
	closed         bool
	dialed         chan bool
	cancel         context.CancelFunc
	ctx            context.Context
	dest           net.Destination
	streamSettings *internet.MemoryStreamConfig
}

// LocalAddr returns nil until the deferred WebSocket dial has completed.
// Without this method, Go promotes LocalAddr from the embedded net.Conn; the
// embedded interface is nil before the first Write, so the promoted call panics.
func (d *delayDialConn) LocalAddr() net.Addr {
	if d.Conn == nil {
		return nil
	}
	return d.Conn.LocalAddr()
}

// RemoteAddr returns nil until the deferred WebSocket dial has completed.
// See LocalAddr for why an explicit method is required here.
func (d *delayDialConn) RemoteAddr() net.Addr {
	if d.Conn == nil {
		return nil
	}
	return d.Conn.RemoteAddr()
}

func (d *delayDialConn) Write(b []byte) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if d.Conn == nil {
		ed := b
		if len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed) {
			ed = nil
		}
		var err error
		if d.Conn, err = dialWebSocket(d.ctx, d.dest, d.streamSettings, ed); err != nil {
			d.Close()
			return 0, errors.New("failed to dial WebSocket").Base(err)
		}
		d.dialed <- true
		if ed != nil {
			return len(ed), nil
		}
	}
	return d.Conn.Write(b)
}

func (d *delayDialConn) Read(b []byte) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if d.Conn == nil {
		select {
		case <-d.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-d.dialed:
		}
	}
	return d.Conn.Read(b)
}

func (d *delayDialConn) Close() error {
	d.closed = true
	d.cancel()
	if d.Conn == nil {
		return nil
	}
	return d.Conn.Close()
}
