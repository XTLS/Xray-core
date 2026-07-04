package goolom

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/protect"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
)

// defaultSTUNURL is the bootstrap STUN server used before the SFU
// advertises its own ICE servers via serverHello. Yandex Telemost
// hands back the real STUN/TURN set in rtcConfiguration.
const defaultSTUNURL = "stun:stun.rtc.yandex.net:3478"

// Connect starts the WebRTC connection process.
func (s *Session) Connect(ctx context.Context) error {
	s.closed.Store(false)
	s.resetMediaState()

	config := webrtc.Configuration{
		ICEServers:   []webrtc.ICEServer{{URLs: []string{defaultSTUNURL}}},
		SDPSemantics: webrtc.SDPSemanticsUnifiedPlan,
	}

	if err := s.setupPeerConnections(config); err != nil {
		return err
	}

	keepAliveCh, sessionCloseCh := s.resetSession()
	var dcReady chan struct{}
	if s.onData != nil {
		var err error
		s.dc, err = s.pcPub.CreateDataChannel("olcrtc", nil)
		if err != nil {
			return fmt.Errorf("create dc: %w", err)
		}
		dcReady = make(chan struct{})
		s.setupDataChannelHandlers(dcReady, sessionCloseCh)
	}

	if err := s.dialWebSocket(); err != nil {
		return err
	}

	s.setupICEHandlers()
	s.startBackgroundGoroutines(ctx, keepAliveCh)

	if s.onData != nil {
		select {
		case <-dcReady:
			return nil
		case <-time.After(15 * time.Second):
			return ErrDataChannelTimeout
		case <-ctx.Done():
			return fmt.Errorf("connect context cancelled: %w", ctx.Err())
		}
	}

	return s.waitForMediaReady(ctx, 20*time.Second)
}

func (s *Session) waitForMediaReady(ctx context.Context, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-s.subscriberConn:
	case <-timer.C:
		return ErrSubscriberMediaTimeout
	case <-ctx.Done():
		return fmt.Errorf("connect context cancelled: %w", ctx.Err())
	}
	return nil
}

func (s *Session) setupPeerConnections(config webrtc.Configuration) error {
	api, err := newWebRTCAPI()
	if err != nil {
		return err
	}

	s.pcSub, err = api.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new sub pc: %w", err)
	}
	s.pcSub.OnConnectionStateChange(s.onSubscriberConnectionStateChange)
	s.pcSub.OnTrack(s.onSubscriberTrack)

	s.pcPub, err = api.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new pub pc: %w", err)
	}
	s.pcPub.OnConnectionStateChange(s.onPublisherConnectionStateChange)

	if err := s.attachPendingVideoTracks(); err != nil {
		return err
	}
	return nil
}

// newWebRTCAPI builds a pion API with IPv4-only ICE and the default media
// engine + interceptors.
func newWebRTCAPI() (*webrtc.API, error) {
	settingEngine := webrtc.SettingEngine{}
	if protect.Protector != nil {
		settingEngine.SetICEProxyDialer(protect.NewProxyDialer())
	}
	settingEngine.LoggerFactory = logger.NewPionLoggerFactory()

	// Restrict ICE to UDP/IPv4. On hosts with many veth/docker interfaces the
	// agent otherwise enumerates dozens of link-local IPv6 candidates that can
	// never reach the SFU ("sendto: network is unreachable"). The flood of dead
	// pairs starves ICE consent-freshness checks on the working pair, so the
	// SFU stops receiving consent and tears down media after ~30-40 s. Limiting
	// to IPv4 keeps the candidate set small and consent alive for the session.
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settingEngine.SetIPFilter(func(ip net.IP) bool {
		return ip.To4() != nil
	})

	// Register the default media engine + interceptors. Without the default
	// interceptors pion never emits RTCP Receiver Reports (or NACK/TWCC) for
	// the inbound tracks, so the SFU sees a silent subscriber and stops
	// forwarding VP8 after ~40 s. Registering them keeps the subscriber path
	// alive for the lifetime of the PC.
	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		return nil, fmt.Errorf("register default codecs: %w", err)
	}
	interceptorRegistry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(mediaEngine, interceptorRegistry); err != nil {
		return nil, fmt.Errorf("register default interceptors: %w", err)
	}
	return webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithInterceptorRegistry(interceptorRegistry),
	), nil
}

// onSubscriberTrack handles a remote track arriving on the subscriber PC.
func (s *Session) onSubscriberTrack(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	if track.Kind() != webrtc.RTPCodecTypeVideo {
		return
	}
	logger.Infof("goolom remote video track: codec=%s stream=%s track=%s",
		track.Codec().MimeType, track.StreamID(), track.ID())
	if cb := s.videoTrackHandler(); cb != nil {
		cb(track, receiver)
	}
	// Drain inbound RTCP on the receiver so the configured interceptors
	// (Receiver Report / NACK / TWCC) keep running. Without an active reader
	// the interceptor chain stalls and the SFU eventually stops forwarding
	// the track.
	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			if _, _, err := receiver.Read(rtcpBuf); err != nil {
				return
			}
		}
	}()
}

func (s *Session) dialWebSocket() error {
	wsDialer := protect.NewWebSocketDialer(wsHandshakeTimeout)
	ws, resp, err := wsDialer.Dial(s.mediaServerURL, nil)
	if err != nil {
		return fmt.Errorf("dial ws: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	s.ws = ws

	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
		return nil
	})
	_ = ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
	return nil
}

func (s *Session) startBackgroundGoroutines(ctx context.Context, keepAliveCh chan struct{}) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.keepAlive(keepAliveCh)
	}()

	_ = s.sendHello()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleSignaling(ctx)
	}()
}

func (s *Session) onConnectionStateChange(state webrtc.PeerConnectionState) {
	if !s.closed.Load() && state == webrtc.PeerConnectionStateFailed {
		s.queueReconnect()
	}
}

func (s *Session) onSubscriberConnectionStateChange(state webrtc.PeerConnectionState) {
	logger.Debugf("goolom subscriber state: %s", state.String())
	switch state {
	case webrtc.PeerConnectionStateConnected:
		s.subscriberReady.Store(true)
		closeSignal(s.subscriberConn)
	case webrtc.PeerConnectionStateDisconnected,
		webrtc.PeerConnectionStateFailed,
		webrtc.PeerConnectionStateClosed:
		s.subscriberReady.Store(false)
	case webrtc.PeerConnectionStateUnknown,
		webrtc.PeerConnectionStateNew,
		webrtc.PeerConnectionStateConnecting:
	}
	s.onConnectionStateChange(state)
}

func (s *Session) onPublisherConnectionStateChange(state webrtc.PeerConnectionState) {
	logger.Debugf("goolom publisher state: %s", state.String())
	switch state {
	case webrtc.PeerConnectionStateConnected:
		s.publisherReady.Store(true)
		closeSignal(s.publisherConn)
	case webrtc.PeerConnectionStateDisconnected,
		webrtc.PeerConnectionStateFailed,
		webrtc.PeerConnectionStateClosed:
		s.publisherReady.Store(false)
		// Publisher failure triggers a full reconnect so the data VP8 track
		// (carried by the publisher PC) is restored. The subscriber PC will
		// also be re-established as part of the full reconnect.
		logger.Warnf("goolom publisher PC %s - triggering reconnect", state)
		s.queueReconnect()
		return
	case webrtc.PeerConnectionStateUnknown,
		webrtc.PeerConnectionStateNew,
		webrtc.PeerConnectionStateConnecting:
	}
	s.onConnectionStateChange(state)
}

// pcCloseTimeout bounds how long teardown waits for a pion
// PeerConnection to close. With the advertised TURN relays now retained
// (issue #95), PeerConnection.Close() tries to free the server-side TURN
// allocation; if that relay is unreachable pion blocks on allocation
// retransmissions for tens of seconds. A stalled close must never hold up
// session teardown or a reconnect, so the close is bounded.
const pcCloseTimeout = 2 * time.Second

// closePeerConns closes the publisher and subscriber PeerConnections
// without letting a stuck TURN deallocation block the caller. Each Close
// runs in its own goroutine; the call returns once both finish or
// pcCloseTimeout elapses, whichever comes first.
func (s *Session) closePeerConns() {
	var wg sync.WaitGroup
	for _, pc := range []*webrtc.PeerConnection{s.pcPub, s.pcSub} {
		if pc == nil {
			continue
		}
		wg.Add(1)
		go func(pc *webrtc.PeerConnection) {
			defer wg.Done()
			_ = pc.Close()
		}(pc)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(pcCloseTimeout):
		logger.Warnf("goolom: peer connection close timed out after %s (stuck TURN dealloc?)", pcCloseTimeout)
	}
}

// sleepCtx waits for d or until ctx is cancelled, returning ctx.Err() when
// the context ends first. It lets the reconnect path bail out promptly
// during shutdown instead of sleeping through a fixed backoff.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("goolom sleep canceled: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// Close terminates the session and releases resources.
func (s *Session) Close() error {
	alreadyClosing := s.closed.Swap(true)
	s.sendQueueClosed.Store(true)

	if !alreadyClosing {
		leaveUID := uuid.New().String()
		leaveAck := s.registerAckWaiter(leaveUID)
		// 2s matches our jitsi tear-down budget. The reason is the same:
		// without giving the server time to register the leave, a
		// back-to-back reconnection from the same client collides with a
		// still-alive ghost participant on the SFU side and inherits
		// stale media-flow state.
		if s.sendLeave(leaveUID) {
			_ = s.waitForAck(leaveUID, leaveAck, 2*time.Second)
		} else {
			s.removeAckWaiter(leaveUID)
		}
	}

	closeSignal(s.closeCh)
	s.stopSession()

	if s.dc != nil {
		_ = s.dc.Close()
	}
	s.closePeerConns()
	if s.ws != nil {
		s.wsMu.Lock()
		_ = s.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second))
		_ = s.ws.Close()
		s.wsMu.Unlock()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return nil
}

// WatchConnection monitors the connection lifecycle and reconnects as needed.
func (s *Session) WatchConnection(ctx context.Context) {
	const maxReconnects = 10
	const reconnectWindow = 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeCh:
			return
		case <-s.reconnectCh:
			if s.handleReconnectAttempt(ctx, maxReconnects, reconnectWindow) {
				return
			}
		}
	}
}

func (s *Session) handleReconnectAttempt(ctx context.Context, maxReconnects int, reconnectWindow time.Duration) bool {
	if time.Since(s.lastReconnect) > reconnectWindow {
		s.reconnectCount = 0
	}
	s.reconnectCount++
	s.lastReconnect = time.Now()

	if s.reconnectCount > maxReconnects {
		s.signalEnded("reconnect limit reached")
		return true
	}

	backoff := time.Duration(s.reconnectCount) * 2 * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	return s.retryReconnect(ctx, backoff)
}

func (s *Session) retryReconnect(ctx context.Context, backoff time.Duration) bool {
	for {
		if err := s.reconnect(ctx); err != nil {
			logger.Debugf("reconnect failed: %v", err)
			select {
			case <-ctx.Done():
				return true
			case <-s.closeCh:
				return true
			case <-time.After(backoff):
				continue
			}
		}
		break
	}
	return false
}

func (s *Session) reconnect(ctx context.Context) error {
	logger.Warnf("goolom: full reconnect triggered")
	s.reconnecting.Store(true)
	defer s.reconnecting.Store(false)

	s.sendLeave(uuid.New().String())
	if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
		return err
	}
	s.stopSession()

	if s.dc != nil {
		_ = s.dc.Close()
	}
	s.closePeerConns()
	if s.ws != nil {
		s.wsMu.Lock()
		_ = s.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second))
		_ = s.ws.Close()
		s.wsMu.Unlock()
	}

	if err := sleepCtx(ctx, 3*time.Second); err != nil {
		return err
	}
	if s.refresh == nil {
		return ErrNoRefresh
	}
	creds, err := s.refresh(ctx)
	if err != nil {
		return fmt.Errorf("reconnect refresh: %w", err)
	}
	s.applyRefreshedCredentials(creds)

	if err := s.Connect(ctx); err != nil {
		return err
	}
	if s.onReconnect != nil {
		s.onReconnect(s.dc)
	}
	s.drainReconnectQueue()
	return nil
}

func (s *Session) applyRefreshedCredentials(creds engine.Credentials) {
	if creds.URL != "" {
		s.mediaServerURL = creds.URL
	}
	if creds.Token != "" {
		s.peerID = creds.Token
	}
	if creds.Extra == nil {
		return
	}
	if v := creds.Extra[credentialKeyRoomID]; v != "" {
		s.roomID = v
	}
	if v := creds.Extra[credentialKeyCredentials]; v != "" {
		s.credentials = v
	}
	if v := creds.Extra[credentialKeyRoomURL]; v != "" {
		s.roomURL = v
	}
	if v := creds.Extra[credentialKeyTelemetryReferer]; v != "" {
		s.telemetryReferer = v
	}
}

func (s *Session) drainReconnectQueue() {
	for {
		select {
		case <-s.reconnectCh:
		default:
			return
		}
	}
}

func (s *Session) queueReconnect() {
	if s.closed.Load() || s.reconnecting.Load() {
		return
	}
	if s.shouldReconnect != nil && !s.shouldReconnect() {
		return
	}
	select {
	case s.reconnectCh <- struct{}{}:
	default:
	}
}

// Reconnect asks the goolom session to tear down its peer connections and
// rejoin the room. Triggered by upper layers when they detect liveness loss
// before the underlying PC has reported failure (silent black-hole on the
// data path).
func (s *Session) Reconnect(reason string) {
	if s.closed.Load() {
		return
	}
	logger.Infof("goolom reconnect requested: %s", reason)
	s.stopSession()
	s.queueReconnect()
}

func (s *Session) stopSession() {
	s.stopTelemetry()
	s.sessionMu.Lock()
	closeSignal(s.keepAliveCh)
	closeSignal(s.sessionCloseCh)
	s.sessionMu.Unlock()
}

func (s *Session) resetSession() (chan struct{}, chan struct{}) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.keepAliveCh = make(chan struct{})
	s.sessionCloseCh = make(chan struct{})
	return s.keepAliveCh, s.sessionCloseCh
}

func (s *Session) resetMediaState() {
	s.subscriberReady.Store(false)
	s.publisherReady.Store(false)
	s.subscriberConn = make(chan struct{})
	s.publisherConn = make(chan struct{})
}

func (s *Session) signalEnded(reason string) {
	s.closed.Store(true)
	s.stopTelemetry()
	if s.onEnded != nil {
		s.onEnded(reason)
	}
}
