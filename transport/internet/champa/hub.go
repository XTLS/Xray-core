package champa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/champa/internal/armor"
	"github.com/xtls/xray-core/transport/internet/champa/internal/encapsulation"
	"github.com/xtls/xray-core/transport/internet/champa/internal/noise"
	"github.com/xtls/xray-core/transport/internet/champa/internal/turbotunnel"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	maxResponsePayload = 5000
	maxResponseDelay   = 100 * time.Millisecond
	serverReadTimeout  = 10 * time.Second
	serverWriteTimeout = 20 * time.Second
	serverIdleTimeout  = idleTimeout
)

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}

// Listen starts an HTTP server on address:port that serves the AMP polling
// protocol. Each smux stream demuxed from a client's KCP+Noise+AMP tunnel is
// surfaced via addConn.
func Listen(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	cfg, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok || cfg == nil {
		return nil, errors.New("champa: missing protocol settings")
	}
	if cfg.Privkey == "" {
		return nil, errors.New("champa: privkey is required")
	}
	privkey, err := hex.DecodeString(cfg.Privkey)
	if err != nil {
		return nil, fmt.Errorf("champa: decode privkey: %w", err)
	}
	if len(privkey) != noise.KeyLen {
		return nil, fmt.Errorf("champa: privkey must be %d bytes, got %d", noise.KeyLen, len(privkey))
	}

	tcpAddr := &net.TCPAddr{IP: address.IP(), Port: int(port)}
	netLn, err := internet.ListenSystem(ctx, tcpAddr, streamSettings.SocketSettings)
	if err != nil {
		return nil, fmt.Errorf("champa: listen TCP: %w", err)
	}
	xerrors.LogInfo(ctx, "champa: listening TCP on ", netLn.Addr())

	noiseConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	plainConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)

	kcpLn, err := kcp.ServeConn(nil, 0, 0, plainConn)
	if err != nil {
		netLn.Close()
		noiseConn.Close()
		plainConn.Close()
		return nil, fmt.Errorf("champa: open KCP listener: %w", err)
	}

	l := &listener{
		ctx:       ctx,
		netLn:     netLn,
		kcpLn:     kcpLn,
		noiseConn: noiseConn,
		plainConn: plainConn,
		addConn:   addConn,
	}

	go func() {
		if err := noiseLoop(noiseConn, plainConn, privkey); err != nil {
			xerrors.LogInfo(ctx, "champa noiseLoop: ", err)
		}
	}()
	go l.acceptSessions()

	l.server = &http.Server{
		Handler:      &handler{pconn: noiseConn},
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}
	go func() {
		if err := l.server.Serve(netLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			xerrors.LogWarningInner(ctx, err, "champa: http server stopped")
		}
	}()

	return l, nil
}

type listener struct {
	ctx       context.Context
	netLn     net.Listener
	server    *http.Server
	kcpLn     *kcp.Listener
	noiseConn *turbotunnel.QueuePacketConn
	plainConn *turbotunnel.QueuePacketConn
	addConn   internet.ConnHandler
	closeOnce sync.Once
}

func (l *listener) Addr() net.Addr { return l.netLn.Addr() }

func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		l.server.Close()
		l.kcpLn.Close()
		l.noiseConn.Close()
		l.plainConn.Close()
	})
	return nil
}

func (l *listener) acceptSessions() {
	for {
		conn, err := l.kcpLn.AcceptKCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return
		}
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(1024, 1024)
		go l.acceptStreams(conn)
	}
}

func (l *listener) acceptStreams(conn *kcp.UDPSession) {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxReceiveBuffer = 16 * 1024 * 1024
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Server(conn, smuxConfig)
	if err != nil {
		conn.Close()
		return
	}
	defer sess.Close()
	defer conn.Close()

	// Synthesize a remote *net.TCPAddr — xray's DestinationFromAddr panics on
	// any net.Addr type other than the three concrete stdlib ones. There's no
	// real TCP peer for an smux stream, so use loopback + low 16 bits of the
	// KCP conv id as a synthetic port.
	remote := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(conn.GetConv() & 0xFFFF),
	}

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return
		}
		l.addConn(stat.Connection(&streamConn{
			Stream: stream,
			local:  l.netLn.Addr(),
			remote: remote,
		}))
	}
}

// noiseLoop is the bidirectional Noise translator between an external
// noiseConn (encrypted Noise messages) and an internal plainConn (KCP). Lifted
// from champa/champa-server/main.go.
func noiseLoop(noiseConn *turbotunnel.QueuePacketConn, plainConn *turbotunnel.QueuePacketConn, privkey []byte) error {
	sessions := make(map[turbotunnel.ClientID]*noise.Session)
	var sessionsLock sync.RWMutex

	for {
		msgType, msg, addr, err := noise.ReadMessageFrom(noiseConn)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		clientID, ok := addr.(turbotunnel.ClientID)
		if !ok {
			continue
		}

		sessionsLock.RLock()
		sess := sessions[clientID]
		sessionsLock.RUnlock()

		switch msgType {
		case noise.MsgTypeHandshakeInit:
			if sess != nil {
				continue
			}
			p := []byte{noise.MsgTypeHandshakeResp}
			newSess, p, err := noise.AcceptHandshake(p, msg, privkey)
			if err != nil {
				continue
			}
			if _, err := noiseConn.WriteTo(p, addr); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return err
			}
			sessionsLock.Lock()
			sessions[clientID] = newSess
			sessionsLock.Unlock()
			go func() {
				defer func() {
					sessionsLock.Lock()
					delete(sessions, clientID)
					sessionsLock.Unlock()
				}()
				for p := range plainConn.OutgoingQueue(clientID) {
					buf := []byte{noise.MsgTypeTransport}
					buf, err := newSess.Encrypt(buf, p)
					if err != nil {
						return
					}
					if _, err := noiseConn.WriteTo(buf, clientID); err != nil {
						if ne, ok := err.(net.Error); ok && ne.Temporary() {
							continue
						}
						return
					}
				}
			}()
		case noise.MsgTypeTransport:
			if sess == nil {
				continue
			}
			p, err := sess.Decrypt(nil, msg)
			if err != nil {
				continue
			}
			plainConn.QueueIncoming(p, clientID)
		}
	}
}

// handler is the AMP polling HTTP handler. Lifted from champa/champa-server/main.go.
type handler struct {
	pconn *turbotunnel.QueuePacketConn
}

func decodeRequest(req *http.Request) (turbotunnel.ClientID, []byte) {
	if !strings.HasPrefix(req.URL.Path, "/0") {
		return turbotunnel.ClientID{}, nil
	}
	_, encoded := path.Split(req.URL.Path[2:])
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return turbotunnel.ClientID{}, nil
	}
	var clientID turbotunnel.ClientID
	n := copy(clientID[:], decoded)
	if n != len(clientID) {
		return turbotunnel.ClientID{}, nil
	}
	return clientID, decoded[n:]
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.Header().Set("Cache-Control", "max-age=15")
	rw.WriteHeader(http.StatusOK)

	enc, err := armor.NewEncoder(rw)
	if err != nil {
		return
	}
	defer enc.Close()

	clientID, payload := decodeRequest(req)
	if payload == nil {
		return
	}

	r := bytes.NewReader(payload)
	for {
		p, err := encapsulation.ReadData(r)
		if err != nil {
			break
		}
		h.pconn.QueueIncoming(p, clientID)
	}

	limit := maxResponsePayload
	timer := time.NewTimer(maxResponseDelay)
	defer timer.Stop()
	first := true
	for {
		var p []byte
		unstash := h.pconn.Unstash(clientID)
		outgoing := h.pconn.OutgoingQueue(clientID)
		select {
		case p = <-unstash:
		default:
			select {
			case p = <-unstash:
			case p = <-outgoing:
			default:
				select {
				case p = <-unstash:
				case p = <-outgoing:
				case <-timer.C:
				}
			}
		}
		timer.Reset(0)

		if len(p) == 0 {
			break
		}

		limit -= len(p)
		if !first && limit < 0 {
			h.pconn.Stash(p, clientID)
			break
		}
		first = false

		if _, err := encapsulation.WriteData(enc, p); err != nil {
			break
		}
		if rwf, ok := rw.(http.Flusher); ok {
			rwf.Flush()
		}
	}
}
