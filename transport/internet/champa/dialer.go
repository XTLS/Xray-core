package champa

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/champa/internal/noise"
	"github.com/xtls/xray-core/transport/internet/champa/internal/turbotunnel"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const idleTimeout = 2 * time.Minute

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

// Dial returns a stat.Connection backed by a single smux stream over a
// long-lived AMP→Noise→KCP→smux session. Sessions are cached per
// (config, dest) so subsequent Dials reuse the same tunnel.
func Dial(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	cfg, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok || cfg == nil {
		return nil, errors.New("champa: missing protocol settings")
	}

	sess, err := getSession(ctx, dest, streamSettings, cfg)
	if err != nil {
		return nil, err
	}

	stream, err := sess.openStream()
	if err != nil {
		return nil, fmt.Errorf("champa: open stream: %w", err)
	}

	// Synthesize concrete *net.TCPAddr for both ends — xray's
	// DestinationFromAddr only accepts the three concrete net.Addr types.
	// dest may carry a domain (e.g. "www.google.com:443") which has no IP yet,
	// so use loopback + dest port as a stand-in. The interesting routing info
	// lives in the outbound's session metadata anyway.
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(dest.Port)}
	return &streamConn{Stream: stream, local: local, remote: remote}, nil
}

type sessionKey struct {
	dest      xnet.Destination
	serverURL string
	cacheURL  string
	front     string
	pubkey    string
}

type champaSession struct {
	mu       sync.Mutex
	smuxSess *smux.Session
	pconn    *pollingPacketConn
	kcpConn  *kcp.UDPSession
	closed   bool
}

func (s *champaSession) openStream() (*smux.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.smuxSess.IsClosed() {
		return nil, errors.New("session closed")
	}
	return s.smuxSess.OpenStream()
}

func (s *champaSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.smuxSess != nil {
		s.smuxSess.Close()
	}
	if s.kcpConn != nil {
		s.kcpConn.Close()
	}
	if s.pconn != nil {
		s.pconn.Close()
	}
}

var (
	sessionCacheMu sync.Mutex
	sessionCache   = map[sessionKey]*champaSession{}
)

func getSession(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig, cfg *Config) (*champaSession, error) {
	key := sessionKey{
		dest:      dest,
		serverURL: cfg.ServerUrl,
		cacheURL:  cfg.CacheUrl,
		front:     cfg.Front,
		pubkey:    cfg.Pubkey,
	}

	sessionCacheMu.Lock()
	sess, ok := sessionCache[key]
	if ok && !sess.smuxSess.IsClosed() {
		sessionCacheMu.Unlock()
		return sess, nil
	}
	if ok {
		// Stale entry — drop it and fall through to rebuild.
		delete(sessionCache, key)
		sess.close()
	}
	sessionCacheMu.Unlock()

	newSess, err := dialSession(ctx, dest, streamSettings, cfg)
	if err != nil {
		return nil, err
	}

	sessionCacheMu.Lock()
	defer sessionCacheMu.Unlock()
	// Race: another caller may have built a session concurrently.
	if existing, ok := sessionCache[key]; ok && !existing.smuxSess.IsClosed() {
		newSess.close()
		return existing, nil
	}
	sessionCache[key] = newSess
	return newSess, nil
}

func dialSession(ctx context.Context, dest xnet.Destination, streamSettings *internet.MemoryStreamConfig, cfg *Config) (*champaSession, error) {
	if cfg.ServerUrl == "" {
		return nil, errors.New("champa: serverUrl is required")
	}
	serverURL, err := url.Parse(cfg.ServerUrl)
	if err != nil {
		return nil, fmt.Errorf("champa: parse serverUrl: %w", err)
	}
	var cacheURL *url.URL
	if cfg.CacheUrl != "" {
		cacheURL, err = url.Parse(cfg.CacheUrl)
		if err != nil {
			return nil, fmt.Errorf("champa: parse cacheUrl: %w", err)
		}
	}
	if cfg.Pubkey == "" {
		return nil, errors.New("champa: pubkey is required")
	}
	pubkey, err := hex.DecodeString(cfg.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("champa: decode pubkey: %w", err)
	}
	if len(pubkey) != noise.KeyLen {
		return nil, fmt.Errorf("champa: pubkey must be %d bytes, got %d", noise.KeyLen, len(pubkey))
	}

	rt := newXrayRoundTripper(dest, streamSettings)

	pconn := newPollingPacketConn(ctx, turbotunnel.DummyAddr{}, func(pctx context.Context, p []byte) (io.ReadCloser, error) {
		return exchangeAMP(pctx, rt, serverURL, cacheURL, cfg.Front, p)
	})

	nconn, err := noiseDial(pconn, turbotunnel.DummyAddr{}, pubkey)
	if err != nil {
		pconn.Close()
		return nil, fmt.Errorf("champa: noise handshake: %w", err)
	}

	kcpConn, err := kcp.NewConn2(turbotunnel.DummyAddr{}, nil, 0, 0, nconn)
	if err != nil {
		pconn.Close()
		return nil, fmt.Errorf("champa: open KCP: %w", err)
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1)
	kcpConn.SetACKNoDelay(true)
	kcpConn.SetWindowSize(1024, 1024)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	smuxSess, err := smux.Client(kcpConn, smuxConfig)
	if err != nil {
		kcpConn.Close()
		pconn.Close()
		return nil, fmt.Errorf("champa: open smux: %w", err)
	}

	return &champaSession{
		smuxSess: smuxSess,
		pconn:    pconn,
		kcpConn:  kcpConn,
	}, nil
}

// noisePacketConn wraps a packet conn with Noise encryption on each datagram.
type noisePacketConn struct {
	sess *noise.Session
	net.PacketConn
}

func readNoiseMessageOfTypeFrom(conn net.PacketConn, wantedType byte) ([]byte, net.Addr, error) {
	for {
		msgType, msg, addr, err := noise.ReadMessageFrom(conn)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return nil, nil, err
		}
		if msgType == wantedType {
			return msg, addr, nil
		}
	}
}

func noiseDial(conn net.PacketConn, addr net.Addr, pubkey []byte) (*noisePacketConn, error) {
	p := []byte{noise.MsgTypeHandshakeInit}
	pre, p, err := noise.InitiateHandshake(p, pubkey)
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(p, addr); err != nil {
		return nil, err
	}
	msg, _, err := readNoiseMessageOfTypeFrom(conn, noise.MsgTypeHandshakeResp)
	if err != nil {
		return nil, err
	}
	sess, err := pre.FinishHandshake(msg)
	if err != nil {
		return nil, err
	}
	return &noisePacketConn{sess, conn}, nil
}

func (c *noisePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	msg, addr, err := readNoiseMessageOfTypeFrom(c.PacketConn, noise.MsgTypeTransport)
	if err != nil {
		return 0, nil, err
	}
	dec, err := c.sess.Decrypt(nil, msg)
	if errors.Is(err, noise.ErrInvalidNonce) {
		return 0, addr, nil
	} else if err != nil {
		return 0, nil, err
	}
	return copy(p, dec), addr, nil
}

func (c *noisePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := []byte{noise.MsgTypeTransport}
	buf, err := c.sess.Encrypt(buf, p)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(buf, addr)
}

// newXrayRoundTripper builds an http.Transport whose underlying TCP dial uses
// xray's internet.DialSystem so streamSettings.SocketSettings (mark, etc.) is
// honored. The actual destination is `dest` from the outbound vnext —
// typically the front domain.
func newXrayRoundTripper(dest xnet.Destination, streamSettings *internet.MemoryStreamConfig) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxConnsPerHost = 2
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Ignore network/addr and route through xray's dial path to the configured destination.
		return internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	}
	return t
}
