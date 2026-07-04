// Package client implements the local SOCKS5 client side of the olcrtc tunnel.
package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/control"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/crypto"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/handshake"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/muxconn"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/names"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/runtime"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/xtaci/smux"
)

var (
	// ErrConnectFailed is returned when a tunnel connection fails.
	ErrConnectFailed = errors.New("tunnel connection failed")
	// ErrProxyAuth is returned when SOCKS proxy authentication fails.
	ErrProxyAuth = errors.New("SOCKS proxy auth failed")
	// ErrKeySize is returned when the encryption key is not 32 bytes.
	// Re-exported from runtime for compatibility with errors.Is callers.
	ErrKeySize = runtime.ErrKeySize
	// ErrInvalidSOCKSVersion is returned when the SOCKS version is not 5.
	ErrInvalidSOCKSVersion = errors.New("invalid socks version")
	// ErrUnsupportedSOCKSCommand is returned for unsupported SOCKS commands.
	ErrUnsupportedSOCKSCommand = errors.New("unsupported socks command")
	// ErrUnsupportedAddressType is returned for unsupported SOCKS address types.
	ErrUnsupportedAddressType = errors.New("unsupported address type")
	// ErrRemoteNotReady is returned when the server-side stream fails to signal readiness.
	ErrRemoteNotReady = errors.New("remote not ready")
	// ErrSOCKSAuthFailed is returned when username/password authentication is rejected.
	ErrSOCKSAuthFailed = errors.New("SOCKS5 authentication failed")
	// ErrSOCKSCredTooLong is returned when a SOCKS5 username or password exceeds 255 bytes.
	ErrSOCKSCredTooLong = errors.New("socks5 user/pass exceeds 255 bytes")
)

// Client handles local SOCKS5 connections and tunnels them to the server.
type Client struct {
	ln          transport.Transport
	cipher      *crypto.Cipher
	conn        *muxconn.Conn
	// controlConn is a separate muxconn wired to the transport's control-plane
	// channel (transport.ControlPlane). When non-nil, the smux control session
	// runs over it instead of the bulk data conn, eliminating head-of-line
	// blocking of control ping/pong behind large data transfers.
	controlConn *muxconn.Conn
	session     *smux.Session
	controlStrm *smux.Stream
	controlStop context.CancelFunc
	sessMu      sync.RWMutex
	reconnectMu sync.Mutex
	health      *runtime.HealthTracker
	deviceID    string
	sessionID   string
	claims      map[string]any
	dnsServer   string
	socksUser   string
	socksPass   string
	// sessionReady is closed (and replaced) each time a session becomes fully
	// established (sessionID != ""). Tunnel handlers wait on it so they do
	// not open smux streams before the server has accepted the handshake.
	sessionReady chan struct{}
}

// HealthFunc is called when the client control health snapshot changes.
type HealthFunc func(control.Status)

// Config holds runtime configuration for [Run] and [RunWithReady].
type Config struct {
	Transport        string
	Carrier          string
	RoomURL          string
	ChannelID        string
	KeyHex           string
	LocalAddr        string
	DNSServer        string
	SOCKSUser        string
	SOCKSPass        string
	TransportOptions transport.Options
	Engine           string
	URL              string
	Token            string
	AuthToken        string
	Liveness         control.Config
	Traffic          transport.TrafficConfig

	// DeviceID overrides the persistent client-side device identifier. Leave
	// empty to derive one from DeviceIDPath (or generate a random one if both
	// are empty).
	DeviceID string

	// DeviceIDPath is a file in which to persist the auto-generated device ID
	// across restarts. Ignored when DeviceID is set explicitly.
	DeviceIDPath string

	// Claims is sent to the server in CLIENT_HELLO and forwarded verbatim to
	// the server's AuthHook. Free-form key/value bag for plan, user, region, etc.
	Claims map[string]any

	// OnHealth receives liveness/reconnect status updates. Nil means no-op.
	OnHealth HealthFunc
}

// Run starts the client with the given configuration.
func Run(ctx context.Context, cfg Config) error {
	return RunWithReady(ctx, cfg, nil)
}

// RunWithReady is like Run but invokes onReady once the local SOCKS listener is up.
func RunWithReady(ctx context.Context, cfg Config, onReady func()) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cipher, err := setupCipher(cfg.KeyHex)
	if err != nil {
		return fmt.Errorf("setupCipher failed: %w", err)
	}

	deviceID, err := resolveDeviceID(cfg.DeviceID, cfg.DeviceIDPath)
	if err != nil {
		return fmt.Errorf("resolve device id: %w", err)
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

	// shutdown is registered BEFORE bringUpLink so we always close any
	// link/session that bringUpLink managed to set up before it
	// errored out. The previous ordering returned early on failure
	// (e.g. handshake timeout against a wedged seichannel transport)
	// without ever calling Close on the carrier link, leaving our MUC
	// presence behind as a ghost participant in the next test that
	// joined the same room. shutdown is nil-safe - it skips fields
	// that bringUpLink hadn't populated yet.
	defer c.shutdown()

	if err := c.bringUpLink(runCtx, cfg, cancel); err != nil {
		return err
	}

	lc := net.ListenConfig{}
	listener, err := lc.Listen(runCtx, "tcp4", cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.LocalAddr, err)
	}
	defer func() { _ = listener.Close() }()

	logger.Infof("SOCKS5 server listening on %s", cfg.LocalAddr)

	if onReady != nil {
		onReady()
	}

	go c.acceptLoop(runCtx, listener)

	<-runCtx.Done()
	return nil
}

func (c *Client) bringUpLink(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
) error {
	ln, err := transport.New(ctx, cfg.Transport, transport.Config{
		Carrier:             cfg.Carrier,
		RoomURL:             cfg.RoomURL,
		Engine:              cfg.Engine,
		URL:                 cfg.URL,
		Token:               cfg.Token,
		AuthToken:           cfg.AuthToken,
		ChannelID:           cfg.ChannelID,
		DeviceID:            c.deviceID,
		Name:                names.Generate(),
		OnData:              c.onData,
		DNSServer:           cfg.DNSServer,
		RequireTargetedPeer: true,
		Options:             cfg.TransportOptions,
		Traffic:             cfg.Traffic,
	})
	if err != nil {
		return fmt.Errorf("failed to create link: %w", err)
	}
	c.ln = ln

	ln.SetEndedCallback(func(reason string) {
		logger.Infof("Client link reported conference end: %s", reason)
		cancel()
	})
	ln.SetShouldReconnect(func() bool { return ctx.Err() == nil })
	ln.SetReconnectCallback(func() {
		if ctx.Err() != nil {
			return
		}
		// Carrier callback fires after the link is back up. If handshake
		// still fails it usually means the server hasn't completed its
		// own reinstall yet - keep the listener up and wait for either
		// another callback or a future liveness loss to re-trigger.
		c.handleReconnect(ctx, cfg, cancel, "carrier")
	})

	if err := ln.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect link: %w", err)
	}

	if err := waitForPeer(ctx, ln); err != nil {
		return err
	}

	c.conn = muxconn.New(ln, c.cipher)
	c.controlConn = muxconn.NewControl(ln, c.cipher)

	sess, controlSess, err := buildSmuxClient(ln, c.conn, c.controlConn)
	if err != nil {
		_ = c.conn.Close()
		if c.controlConn != nil {
			_ = c.controlConn.Close()
		}
		return err
	}

	control, sid, err := openControlStream(ctx, controlSess, c.deviceID, c.claims)
	if err != nil {
		_ = sess.Close()
		if controlSess != sess {
			_ = controlSess.Close()
		}
		_ = c.conn.Close()
		if c.controlConn != nil {
			_ = c.controlConn.Close()
		}
		return fmt.Errorf("handshake: %w", err)
	}
	logger.Infof("session %s opened (device=%s)", sid, c.deviceID)

	c.sessMu.Lock()
	c.session = sess
	c.controlStrm = control
	c.sessionID = sid
	c.sessMu.Unlock()
	c.signalSessionReady()
	c.recordSession(sid)
	c.startControlLoop(ctx, cfg, cancel, control)

	go ln.WatchConnection(ctx)
	return nil
}

// peerWaitTimeout bounds how long bringUpLink/tryReopenSession will block
// waiting for the remote peer to appear before giving up. Without a bound a
// missing peer (server offline, wrong room, never joins) would hang the
// caller indefinitely — before the SOCKS listener is even created — instead
// of surfacing a failure. We reuse the handshake timeout so a missing peer
// fails on the same ~15s budget as a wedged handshake would.
const peerWaitTimeout = handshake.DefaultTimeout

// waitForPeer blocks until the transport reports a remote peer is ready, the
// peer-wait deadline elapses, or ctx is cancelled. Transports that don't
// implement PeerReadyTransport return immediately.
func waitForPeer(ctx context.Context, ln transport.Transport) error {
	waiter, ok := ln.(transport.PeerReadyTransport)
	if !ok {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, peerWaitTimeout)
	defer cancel()
	if err := waiter.WaitForPeer(waitCtx); err != nil {
		return fmt.Errorf("wait for peer: %w", err)
	}
	return nil
}

// buildSmuxClient creates the bulk-data smux session over conn and, when the
// transport exposes an isolated control plane (controlConn != nil), a separate
// smux session over controlConn for handshake/control traffic. When there is
// no control plane the bulk session doubles as the control session. On error
// any session opened here is closed; the caller owns conn/controlConn.
func buildSmuxClient(
	ln transport.Transport,
	conn, controlConn *muxconn.Conn,
) (*smux.Session, *smux.Session, error) {
	sess, err := smux.Client(conn, runtime.SmuxConfigFor(ln))
	if err != nil {
		return nil, nil, fmt.Errorf("smux client: %w", err)
	}
	if controlConn == nil {
		return sess, sess, nil
	}
	// Separate smux session for the control stream only: small buffers, no
	// smux keepalive (our own control.Run ping/pong handles liveness).
	controlSess, err := smux.Client(controlConn, controlSmuxConfig(linkMaxPayload(ln)))
	if err != nil {
		_ = sess.Close()
		return nil, nil, fmt.Errorf("control smux client: %w", err)
	}
	return sess, controlSess, nil
}

// openControlStream opens stream #1 on sess and performs the handshake.
// The stream stays open for the lifetime of the smux session and carries
// post-handshake control messages.
func openControlStream(
	ctx context.Context,
	sess *smux.Session,
	deviceID string,
	claims map[string]any,
) (*smux.Stream, string, error) {
	return openControlStreamTimeout(ctx, sess, deviceID, claims, handshake.DefaultTimeout)
}

func openControlStreamTimeout(
	ctx context.Context,
	sess *smux.Session,
	deviceID string,
	claims map[string]any,
	timeout time.Duration,
) (*smux.Stream, string, error) {
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, "", fmt.Errorf("open control stream: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer close(done)
	_ = stream.SetDeadline(time.Now().Add(timeout))
	sid, err := handshake.Client(stream, deviceID, claims)
	_ = stream.SetDeadline(time.Time{})
	if err != nil {
		_ = stream.Close()
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("handshake client: %w", ctx.Err())
		}
		return nil, "", fmt.Errorf("handshake client: %w", err)
	}
	return stream, sid, nil
}

// resolveDeviceID returns the device ID to send in CLIENT_HELLO.
//
// Precedence:
//  1. Explicit deviceID arg (Config.DeviceID) - used verbatim.
//  2. Persistent file at path (Config.DeviceIDPath) - read if it exists,
//     otherwise generated and written for future runs.
//  3. Random UUID per run when both inputs are empty.
func resolveDeviceID(deviceID, path string) (string, error) {
	if deviceID != "" {
		return deviceID, nil
	}
	if path == "" {
		return uuid.NewString(), nil
	}
	// #nosec G304 -- persistent device ID path is explicit user configuration.
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read device id %s: %w", path, err)
	}
	id := uuid.NewString()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("mkdir device id dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write device id %s: %w", path, err)
	}
	return id, nil
}

func smuxConfig(maxWirePayload int) *smux.Config {
	return runtime.SmuxConfig(maxWirePayload)
}

// controlSmuxConfig returns a lean smux config for the isolated control-plane
// session. The control session carries only ping/pong frames, so we use
// small buffers and disable smux keepalives (our own control.Run ping loop
// handles liveness).
func controlSmuxConfig(maxWirePayload int) *smux.Config {
	return runtime.ControlSmuxConfig(maxWirePayload)
}

func linkMaxPayload(tr transport.Transport) int {
	return runtime.MaxPayload(tr)
}

func (c *Client) handleReconnect(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.recordReconnect()
	logger.Infof("client reconnect reason=%s - tearing down smux session", reason)
	c.resetLinkPeer()

	// Close the old muxconns immediately so any in-flight Push from data
	// arriving on the new bridge is discarded. Without this, the server
	// side that reconnected faster can push frames into our old muxconn,
	// corrupting the dying smux session.
	c.sessMu.RLock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.controlConn != nil {
		_ = c.controlConn.Close()
	}
	c.sessMu.RUnlock()

	// Install fresh muxconns immediately so onData never hits nil while
	// the old session is being torn down. tryReopenSession will swap them
	// again with its own conns on each attempt.
	newConn := muxconn.New(c.ln, c.cipher)
	newControlConn := muxconn.NewControl(c.ln, c.cipher)

	c.sessMu.Lock()
	oldControl := c.controlStrm
	oldControlStop := c.controlStop
	oldSess := c.session
	c.conn = newConn
	c.controlConn = newControlConn
	c.session = nil
	c.controlStrm = nil
	c.controlStop = nil
	c.sessionID = ""
	c.sessMu.Unlock()

	if oldControlStop != nil {
		oldControlStop()
	}
	if oldSess != nil {
		_ = oldSess.Close()
	}
	if oldControl != nil {
		_ = oldControl.Close()
	}

	// When liveness on top of a still-"connected" carrier expires, the
	// underlying ICE/data path has gone silent without the engine noticing.
	// Re-handshaking over the dead carrier just times out repeatedly, so
	// ask the carrier to rebuild itself; the new carrier will fire its own
	// reconnect callback which then drives a fresh handshake.
	if reason == "liveness" && c.ln != nil {
		c.ln.Reconnect("liveness")
		// Return immediately - retryHandshake over the dead link would
		// loop forever with "open control stream: timeout" while holding
		// reconnectMu, blocking the carrier callback that fires once the
		// link is actually back up. Let that callback (reason="carrier")
		// drive the handshake when the transport is ready.
		return
	}

	c.retryHandshake(ctx, cfg, cancel, reason)
}

func (c *Client) retryHandshake(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	const (
		initialDelay = 300 * time.Millisecond
		maxDelay     = 5 * time.Second
	)
	delay := initialDelay
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		logger.Infof("client reconnect attempt=%d reason=%s", attempt, reason)
		if c.tryReopenSession(ctx, cfg, cancel, attempt) {
			return
		}
		// Don't fail the whole process on liveness reconnect: the carrier
		// rebuild may take dozens of seconds (e.g. ICE restart on a flaky
		// network). Keep the SOCKS5 listener open and wait - handleSocks5
		// will return host-unreachable to clients until we recover. For
		// carrier-driven reconnects the callback fires after the link is
		// already up, so a missed handshake is more suspicious; cap it.
		if reason == "carrier" && attempt >= 5 {
			logger.Warnf("client reconnect: exhausted %d handshake attempts (reason=%s) - keeping listener up", attempt, reason)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func (c *Client) resetLinkPeer() {
	c.sessMu.RLock()
	ln := c.ln
	c.sessMu.RUnlock()
	if resetter, ok := ln.(interface{ ResetPeer() }); ok {
		resetter.ResetPeer()
	}
}

func (c *Client) tryReopenSession(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
	attempt int,
) bool {
	conn := muxconn.New(c.ln, c.cipher)

	// If the transport has an isolated control plane, build a second muxconn
	// wired to it. The smux control stream will run over controlConn so that
	// bulk data writes on conn can never head-of-line block control ping/pong.
	controlConn := muxconn.NewControl(c.ln, c.cipher)

	c.sessMu.Lock()
	oldConn := c.conn
	oldCtrl := c.controlConn
	c.conn = conn
	c.controlConn = controlConn
	c.sessMu.Unlock()
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldCtrl != nil {
		_ = oldCtrl.Close()
	}

	sess, controlSess, err := buildSmuxClient(c.ln, conn, controlConn)
	if err != nil {
		logger.Warnf("smux re-init failed (attempt %d): %v", attempt, err)
		return false
	}

	// Wait for the peer to re-announce before opening the control stream.
	// resetLinkPeer cleared the peer epoch on reconnect, so without this the
	// client's first SYN can race ahead of the server's bridge being open
	// again — the same handshake-ordering race WaitForPeer guards against on
	// the initial connect. The retry/backoff loop would eventually recover,
	// but only after a full handshake timeout per attempt.
	if err := waitForPeer(ctx, c.ln); err != nil {
		logger.Warnf("wait for peer on reconnect failed (attempt %d): %v", attempt, err)
		_ = sess.Close()
		if controlSess != sess {
			_ = controlSess.Close()
		}
		return false
	}

	ctrlStream, sid, err := openControlStreamTimeout(ctx, controlSess, c.deviceID, c.claims, handshake.DefaultTimeout)
	if err != nil {
		logger.Warnf("handshake on reconnect failed (attempt %d): %v", attempt, err)
		_ = sess.Close()
		if controlSess != sess {
			_ = controlSess.Close()
		}
		return false
	}
	logger.Infof("session %s reopened (device=%s)", sid, c.deviceID)
	c.sessMu.Lock()
	c.session = sess
	c.controlStrm = ctrlStream
	c.sessionID = sid
	c.sessMu.Unlock()
	c.signalSessionReady()
	c.recordSession(sid)
	c.startControlLoop(ctx, cfg, cancel, ctrlStream)
	return true
}

func (c *Client) startControlLoop(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
	stream *smux.Stream,
) {
	controlCtx, stop := context.WithCancel(ctx)
	c.sessMu.Lock()
	c.controlStop = stop
	c.sessMu.Unlock()

	liveness := cfg.Liveness
	// Relax the pong timeout only for transports with an isolated control
	// plane (vp8channel): KCP batching + frame pacing can delay control
	// packets under load. Conventional carriers (jitsi/datachannel) keep the
	// conservative default so a dead link is detected promptly. A user-set
	// timeout larger than the default is left untouched.
	if runtime.IsControlPlane(c.ln) && liveness.Timeout <= control.DefaultTimeout {
		liveness.Timeout = runtime.LivenessTimeout(c.ln)
	}
	onPong := liveness.OnPong
	onMissedPong := liveness.OnMissedPong
	onUnhealthy := liveness.OnUnhealthy
	liveness.OnPong = func(h control.Health) {
		c.sessMu.RLock()
		sid := c.sessionID
		c.sessMu.RUnlock()
		c.recordPong(h)
		logger.Debugf("control alive session=%s rtt=%v seq=%d", sid, h.RTT, h.Seq)
		if onPong != nil {
			onPong(h)
		}
	}
	liveness.OnMissedPong = func(missed int) {
		c.recordMissed(missed)
		logger.Warnf("control missed pong on client: missed_pongs=%d", missed)
		if onMissedPong != nil {
			onMissedPong(missed)
		}
	}
	liveness.OnUnhealthy = func(missed int) {
		c.recordUnhealthy(missed)
		logger.Warnf("control stream unhealthy on client: missed_pongs=%d", missed)
		if onUnhealthy != nil {
			onUnhealthy(missed)
		}
	}

	go func() {
		err := control.Run(controlCtx, stream, liveness)
		if controlCtx.Err() != nil || ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.Warnf("client control stream ended: %v", err)
		}
		// handleReconnect now retries indefinitely on liveness so it only
		// returns false on ctx cancellation; don't tear down the client.
		c.handleReconnect(ctx, cfg, cancel, "liveness")
	}()
}

// Status returns the latest client-side control health snapshot.
func (c *Client) Status() control.Status {
	return c.health.Status()
}

func (c *Client) recordSession(sessionID string) { c.health.RecordSession(sessionID) }
func (c *Client) recordPong(h control.Health)    { c.health.RecordPong(h) }
func (c *Client) recordMissed(missed int)        { c.health.RecordMissed(missed) }
func (c *Client) recordUnhealthy(missed int)     { c.health.RecordUnhealthy(missed) }
func (c *Client) recordReconnect()               { c.health.RecordReconnect() }

// signalSessionReady closes the current sessionReady channel (waking any
// waiters) and replaces it with a fresh one for the next reconnect cycle.
func (c *Client) signalSessionReady() {
	c.sessMu.Lock()
	old := c.sessionReady
	c.sessionReady = make(chan struct{})
	c.sessMu.Unlock()
	close(old)
}

// waitSessionReady blocks until the session is fully established (sessionID !=
// "") or ctx is cancelled. Returns the ready channel to select on.
func (c *Client) readyChannel() chan struct{} {
	c.sessMu.RLock()
	ch := c.sessionReady
	c.sessMu.RUnlock()
	return ch
}

func (c *Client) shutdown() {
	c.sessMu.Lock()
	control := c.controlStrm
	controlStop := c.controlStop
	sess := c.session
	conn := c.conn
	ctrlConn := c.controlConn
	c.controlStrm = nil
	c.controlStop = nil
	c.session = nil
	c.conn = nil
	c.controlConn = nil
	c.sessMu.Unlock()

	notifyControlClose(control)
	if controlStop != nil {
		controlStop()
	}
	if sess != nil {
		_ = sess.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if ctrlConn != nil {
		_ = ctrlConn.Close()
	}
	if c.ln != nil {
		_ = c.ln.Close()
	}
	if control != nil {
		_ = control.Close()
	}
}

func notifyControlClose(stream *smux.Stream) {
	if stream == nil {
		return
	}
	_ = stream.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := control.SendClose(stream); err == nil {
		time.Sleep(200 * time.Millisecond)
	}
	_ = stream.SetWriteDeadline(time.Time{})
	_ = stream.CloseWrite()
}

func setupCipher(keyHex string) (*crypto.Cipher, error) {
	cipher, err := runtime.SetupCipher(keyHex)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	return cipher, nil
}

func (c *Client) onData(data []byte) {
	c.sessMu.RLock()
	conn := c.conn
	c.sessMu.RUnlock()
	if conn != nil {
		conn.Push(data)
	}
}

func (c *Client) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warnf("Accept error: %v", err)
				continue
			}
		}
		go c.handleSocks5(ctx, conn)
	}
}

func (c *Client) handleSocks5(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := c.socks5Handshake(conn); err != nil {
		return
	}

	targetAddr, targetPort, err := c.socks5Request(conn)
	if err != nil {
		return
	}

	// Wait until the session handshake is fully complete (sessionID != "").
	// Without this gate, tunnel streams opened during server-side reinstall
	// land on a dying smux session and get "closed pipe".
	const sessionReadyTimeout = 60 * time.Second
	readyCtx, cancel := context.WithTimeout(ctx, sessionReadyTimeout)
	defer cancel()
	for {
		c.sessMu.RLock()
		sess := c.session
		sid := c.sessionID
		c.sessMu.RUnlock()
		if sess != nil && !sess.IsClosed() && sid != "" {
			c.tunnel(conn, sess, targetAddr, targetPort)
			return
		}
		// sess is nil (no session yet) or closed (reconnect in progress) —
		// in both cases wait for readyChannel rather than failing immediately.
		// A closed session means handleReconnect is running; a fresh session
		// will be installed shortly by tryReopenSession.
		select {
		case <-readyCtx.Done():
			_, _ = conn.Write(replyHostUnreachable())
			return
		case <-c.readyChannel():
			// session became ready; re-check
		}
	}
}

func (c *Client) tunnel(conn net.Conn, sess *smux.Session, targetAddr string, targetPort int) {
	stream, err := sess.OpenStream()
	if err != nil {
		logger.Warnf("OpenStream failed: %v", err)
		_, _ = conn.Write(replyHostUnreachable())
		return
	}
	defer func() { _ = stream.Close() }()

	logger.Infof("sid=%d tunnel to %s:%d", stream.ID(), targetAddr, targetPort)

	if err := c.sendConnectRequest(stream, targetAddr, targetPort); err != nil {
		logger.Warnf("sid=%d connect failed: %v", stream.ID(), err)
		_, _ = conn.Write(replyHostUnreachable())
		return
	}

	if _, err := conn.Write(replySuccess()); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(stream, conn)
		_ = stream.Close()
	}()
	_, _ = io.Copy(conn, stream)
}

func (c *Client) sendConnectRequest(stream *smux.Stream, targetAddr string, targetPort int) error {
	connectReq, err := json.Marshal(map[string]any{
		"cmd":  "connect",
		"addr": targetAddr,
		"port": targetPort,
	})
	if err != nil {
		return fmt.Errorf("sid=%d marshal connect req: %w", stream.ID(), err)
	}

	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Write(connectReq); err != nil {
		return fmt.Errorf("sid=%d write connect req: %w", stream.ID(), err)
	}
	_ = stream.SetWriteDeadline(time.Time{})

	ack := make([]byte, 1)
	// ControlPlane transports (vp8channel peer-routing) may take ~30s for the
	// SFU to complete renegotiation and start forwarding data frames, so they
	// get a generous deadline. Conventional carriers (jitsi/datachannel) use
	// the conservative window so a stuck CONNECT fails fast.
	_ = stream.SetReadDeadline(time.Now().Add(runtime.ConnectAckTimeout(c.ln)))
	if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 0x00 {
		return fmt.Errorf("sid=%d: %w (read_err=%w ack=%v)", stream.ID(), ErrRemoteNotReady, err, ack)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return nil
}

func (c *Client) socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read socks5 header: %w", err)
	}
	if buf[0] != 5 {
		return fmt.Errorf("%w: %d", ErrInvalidSOCKSVersion, buf[0])
	}
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read socks5 methods: %w", err)
	}

	if c.socksUser != "" {
		// RFC 1929: method 0x02 = username/password auth.
		if _, err := conn.Write([]byte{5, 2}); err != nil {
			return fmt.Errorf("write socks5 auth method: %w", err)
		}
		if err := c.socks5UserPassAuth(conn); err != nil {
			return err
		}
		return nil
	}

	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return fmt.Errorf("write socks5 auth: %w", err)
	}
	return nil
}

func (c *Client) socks5UserPassAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks5 auth header: %w", err)
	}
	if header[0] != 0x01 {
		return fmt.Errorf("%w: expected auth version 1, got %d", ErrInvalidSOCKSVersion, header[0])
	}
	ulen := int(header[1])
	userBuf := make([]byte, ulen)
	if _, err := io.ReadFull(conn, userBuf); err != nil {
		return fmt.Errorf("read socks5 username: %w", err)
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("read socks5 plen: %w", err)
	}

	plen := int(plenBuf[0])
	passBuf := make([]byte, plen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return fmt.Errorf("read socks5 password: %w", err)
	}

	if string(userBuf) != c.socksUser || string(passBuf) != c.socksPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return ErrSOCKSAuthFailed
	}

	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("write socks5 auth success: %w", err)
	}

	return nil
}

func (c *Client) socks5Request(conn net.Conn) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, fmt.Errorf("read socks5 request: %w", err)
	}
	if header[1] != 1 {
		return "", 0, fmt.Errorf("%w: %d", ErrUnsupportedSOCKSCommand, header[1])
	}

	addr, err := c.readSocks5Addr(conn, header[3])
	if err != nil {
		return "", 0, err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, fmt.Errorf("read socks5 port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return addr, port, nil
}

func (c *Client) readSocks5Addr(conn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case 1: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read socks5 ipv4: %w", err)
		}
		return net.IP(buf).String(), nil
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read socks5 domain len: %w", err)
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read socks5 domain: %w", err)
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("%w: %d", ErrUnsupportedAddressType, addrType)
	}
}

func replySuccess() []byte {
	return []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
}

func replyHostUnreachable() []byte {
	return []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}
}
