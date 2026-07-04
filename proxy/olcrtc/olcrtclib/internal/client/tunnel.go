package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/control"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/runtime"
)

// Tunnel is a live client-side carrier session. It brings up the WebRTC
// carrier, completes the handshake and runs the background control/reconnect
// loops, but - unlike Run - it does NOT start a local SOCKS5 listener. Callers
// open one multiplexed stream per target connection via DialContext.
//
// A Tunnel is safe for concurrent use: DialContext may be called from many
// goroutines at once, each obtaining an independent smux stream over the shared
// carrier.
type Tunnel struct {
	c      *Client
	cancel context.CancelFunc
}

// StartTunnel brings up the carrier link described by cfg and returns a Tunnel
// ready for DialContext. The tunnel keeps running (reconnecting as needed)
// until Close is called or the ctx passed here is cancelled.
func StartTunnel(ctx context.Context, cfg Config) (*Tunnel, error) {
	runCtx, cancel := context.WithCancel(ctx)

	cipher, err := setupCipher(cfg.KeyHex)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("setupCipher failed: %w", err)
	}

	deviceID, err := resolveDeviceID(cfg.DeviceID, cfg.DeviceIDPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("resolve device id: %w", err)
	}

	c := &Client{
		cipher:       cipher,
		deviceID:     deviceID,
		claims:       cfg.Claims,
		dnsServer:    cfg.DNSServer,
		socksUser:    cfg.SOCKSUser,
		socksPass:    cfg.SOCKSPass,
		health:       runtime.NewHealthTracker(cfg.OnHealth),
		sessionReady: make(chan struct{}),
	}

	if err := c.bringUpLink(runCtx, cfg, cancel); err != nil {
		c.shutdown()
		cancel()
		return nil, err
	}

	return &Tunnel{c: c, cancel: cancel}, nil
}

// DialContext opens a new tunnel stream to addr:port, sends the CONNECT request,
// waits for the server to acknowledge readiness, and returns a net.Conn that
// carries the tunneled bytes. The returned conn is backed by a single smux
// stream over the shared carrier; closing it closes just that stream.
//
// If the carrier is mid-reconnect, DialContext blocks (up to an internal
// timeout, or until ctx is cancelled) for the session to become ready again,
// mirroring the local SOCKS5 path.
func (t *Tunnel) DialContext(ctx context.Context, addr string, port int) (net.Conn, error) {
	const sessionReadyTimeout = 60 * time.Second
	readyCtx, cancel := context.WithTimeout(ctx, sessionReadyTimeout)
	defer cancel()

	for {
		t.c.sessMu.RLock()
		sess := t.c.session
		sid := t.c.sessionID
		t.c.sessMu.RUnlock()

		if sess != nil && !sess.IsClosed() && sid != "" {
			stream, err := sess.OpenStream()
			if err != nil {
				return nil, fmt.Errorf("open stream: %w", err)
			}
			if err := t.c.sendConnectRequest(stream, addr, port); err != nil {
				_ = stream.Close()
				return nil, fmt.Errorf("connect %s:%d: %w", addr, port, err)
			}
			// *smux.Stream implements net.Conn.
			return stream, nil
		}

		select {
		case <-readyCtx.Done():
			return nil, fmt.Errorf("olcrtc tunnel not ready: %w", readyCtx.Err())
		case <-t.c.readyChannel():
			// session became ready (or reconnected); re-check
		}
	}
}

// Status returns the latest client-side control health snapshot.
func (t *Tunnel) Status() control.Status { return t.c.Status() }

// Close tears down the tunnel and releases all carrier resources.
func (t *Tunnel) Close() error {
	t.cancel()
	t.c.shutdown()
	return nil
}
