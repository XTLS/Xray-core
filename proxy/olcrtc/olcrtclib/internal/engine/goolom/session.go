// Package goolom implements an engine.Session backed by the Goolom SFU
// signaling protocol. Goolom is the proprietary SFU developed for Yandex
// Telemost; the on-wire protocol - capabilities offer, separated subscriber
// and publisher PeerConnections, ack/pong keepalive, slots-based subscribe
// model - is what this engine speaks.
//
// HTTP auth (room-info lookup, telemetry referer, etc.) lives in the auth
// package; this engine consumes a media-server WebSocket URL plus the
// peer/room/credentials tuple supplied as engine.Config.
package goolom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	"github.com/pion/webrtc/v4"
)

const (
	realDataChannelMessageLimit = 12288
	defaultSendDelayLow         = 2 * time.Millisecond
	defaultSendDelayMax         = 12 * time.Millisecond
	defaultTelemetryInterval    = 20 * time.Second
	defaultSendQueueSize        = 5000
	defaultBufferHighWaterMark  = 512 * 1024
	defaultSendQueueCapHard     = 4000

	wsReadTimeout      = 60 * time.Second
	wsHandshakeTimeout = 15 * time.Second

	keyUID          = "uid"
	keyDescription  = "description"
	keyPcSeq        = "pcSeq"
	keyName         = "name"
	stateTerminated = "terminated"

	credentialKeyRoomID           = "roomID"
	credentialKeyCredentials      = "credentials"
	credentialKeyRoomURL          = "roomURL"
	credentialKeyTelemetryReferer = "telemetryReferer"
)

var (
	// ErrDataChannelTimeout is returned when the DataChannel fails to open in time.
	ErrDataChannelTimeout = errors.New("datachannel timeout")
	// ErrDataChannelNotReady is returned when send is called before the DataChannel is open.
	ErrDataChannelNotReady = errors.New("datachannel not ready")
	// ErrSendQueueClosed is returned when send is called after Close.
	ErrSendQueueClosed = errors.New("send queue closed")
	// ErrSendQueueTimeout is returned when the send queue cannot accept new data in time.
	ErrSendQueueTimeout = errors.New("send queue timeout")
	// ErrSessionClosed is returned when the session is closed mid-operation.
	ErrSessionClosed = errors.New("session closed")
	// ErrPeerClosed is returned when the peer is closed mid-operation.
	ErrPeerClosed = errors.New("peer closed")
	// ErrSubscriberMediaTimeout is returned when the subscriber media is not ready in time.
	ErrSubscriberMediaTimeout = errors.New("subscriber media timeout")
	// ErrPublisherNotInitialized is returned when the publisher PC is not set up.
	ErrPublisherNotInitialized = errors.New("publisher peer connection not initialized")
	// ErrURLRequired is returned when no media-server WebSocket URL was supplied.
	ErrURLRequired = errors.New("goolom media server URL required")
	// ErrRoomIDRequired is returned when no room ID was supplied.
	ErrRoomIDRequired = errors.New("goolom room ID required")
	// ErrPeerIDRequired is returned when no peer ID was supplied.
	ErrPeerIDRequired = errors.New("goolom peer ID required")
	// ErrNoRefresh is returned when reconnect is attempted without a refresh callback.
	ErrNoRefresh = errors.New("goolom reconnect: no refresh callback supplied")
)

// TrafficShape controls outgoing data-channel pacing.
type TrafficShape struct {
	MaxMessageSize int
	MinDelay       time.Duration
	MaxDelay       time.Duration
}

// Session is the Goolom engine handle.
type Session struct {
	name             string
	mediaServerURL   string
	peerID           string
	roomID           string
	credentials      string
	roomURL          string // referer for telemetry - opaque to the engine
	telemetryReferer string
	refresh          func(ctx context.Context) (engine.Credentials, error)

	ws    *websocket.Conn
	wsMu  sync.Mutex
	pcSub *webrtc.PeerConnection
	pcPub *webrtc.PeerConnection
	dc    *webrtc.DataChannel

	onData          func([]byte)
	onReconnect     func(*webrtc.DataChannel)
	shouldReconnect func() bool
	onEnded         func(string)

	reconnectCh    chan struct{}
	closeCh        chan struct{}
	keepAliveCh    chan struct{}
	telemetryCh    chan struct{}
	sessionCloseCh chan struct{}
	lastReconnect  time.Time
	reconnectCount int
	sessionMu      sync.Mutex

	sendQueue       chan []byte
	sendQueueClosed atomic.Bool
	closed          atomic.Bool
	reconnecting    atomic.Bool
	telemetryActive atomic.Bool

	ackMu      sync.Mutex
	ackWaiters map[string]chan struct{}

	trafficShape TrafficShape

	videoTrackMu    sync.RWMutex
	videoTracks     []webrtc.TrackLocal
	onVideoTrack    func(*webrtc.TrackRemote, *webrtc.RTPReceiver)
	subscriberReady atomic.Bool
	publisherReady  atomic.Bool
	subscriberConn  chan struct{}
	publisherConn   chan struct{}
	wg              sync.WaitGroup

	httpClient *http.Client
}

// New creates a new Goolom engine session.
//
// cfg.URL is the media server WebSocket URL. cfg.Token carries the peer ID.
// cfg.Extra carries the rest of the room tuple: roomID, credentials, and an
// optional roomURL / telemetryReferer string the engine uses verbatim as the
// Referer header for telemetry posts.
func New(_ context.Context, cfg engine.Config) (engine.Session, error) {
	if cfg.URL == "" {
		return nil, ErrURLRequired
	}
	peerID := cfg.Token
	if peerID == "" {
		return nil, ErrPeerIDRequired
	}
	roomID := ""
	credentials := ""
	roomURL := ""
	telemetryReferer := ""
	if cfg.Extra != nil {
		roomID = cfg.Extra[credentialKeyRoomID]
		credentials = cfg.Extra[credentialKeyCredentials]
		roomURL = cfg.Extra[credentialKeyRoomURL]
		telemetryReferer = cfg.Extra[credentialKeyTelemetryReferer]
	}
	if roomID == "" {
		return nil, ErrRoomIDRequired
	}
	if telemetryReferer == "" {
		telemetryReferer = roomURL
	}

	return &Session{
		name:             cfg.Name,
		mediaServerURL:   cfg.URL,
		peerID:           peerID,
		roomID:           roomID,
		credentials:      credentials,
		roomURL:          roomURL,
		telemetryReferer: telemetryReferer,
		refresh:          cfg.Refresh,
		onData:           cfg.OnData,
		reconnectCh:      make(chan struct{}, 1),
		closeCh:          make(chan struct{}),
		keepAliveCh:      make(chan struct{}),
		sessionCloseCh:   make(chan struct{}),
		telemetryCh:      make(chan struct{}, 1),
		sendQueue:        make(chan []byte, defaultSendQueueSize),
		ackWaiters:       make(map[string]chan struct{}),
		subscriberConn:   make(chan struct{}),
		publisherConn:    make(chan struct{}),
		trafficShape: TrafficShape{
			MaxMessageSize: realDataChannelMessageLimit,
			MinDelay:       defaultSendDelayLow,
			MaxDelay:       defaultSendDelayMax,
		},
		httpClient: nil,
	}, nil
}

// Capabilities reports what this engine can do.
func (s *Session) Capabilities() engine.Capabilities {
	return engine.Capabilities{ByteStream: true, VideoTrack: true}
}

// SetTrafficShape adjusts the outgoing data-channel pacing.
func (s *Session) SetTrafficShape(shape TrafficShape) {
	if shape.MaxMessageSize <= 0 {
		shape.MaxMessageSize = realDataChannelMessageLimit
	}
	if shape.MaxDelay < shape.MinDelay {
		shape.MaxDelay = shape.MinDelay
	}
	s.trafficShape = shape
}

// Send queues data for transmission.
func (s *Session) Send(data []byte) error {
	if s.dc == nil || s.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return ErrDataChannelNotReady
	}
	if s.sendQueueClosed.Load() {
		return ErrSendQueueClosed
	}
	select {
	case s.sendQueue <- data:
		return nil
	case <-time.After(50 * time.Millisecond):
		return ErrSendQueueTimeout
	}
}

// GetSendQueue returns the transmission queue.
func (s *Session) GetSendQueue() chan []byte { return s.sendQueue }

// GetBufferedAmount returns the WebRTC buffered amount.
func (s *Session) GetBufferedAmount() uint64 {
	if s.dc != nil {
		return s.dc.BufferedAmount()
	}
	return 0
}

// SetEndedCallback sets the callback for connection termination.
func (s *Session) SetEndedCallback(cb func(string)) { s.onEnded = cb }

// SetReconnectCallback sets the callback for reconnection events.
func (s *Session) SetReconnectCallback(cb func(*webrtc.DataChannel)) { s.onReconnect = cb }

// SetShouldReconnect sets the policy for reconnection.
func (s *Session) SetShouldReconnect(fn func() bool) { s.shouldReconnect = fn }

// SubscriberCanSend reports whether the subscriber PC is connected.
// Unlike CanSend, it does not require publisherReady, so it returns true
// as soon as SFU data can arrive — before the publisher PC negotiates.
func (s *Session) SubscriberCanSend() bool {
	return !s.closed.Load() && s.subscriberReady.Load()
}

// CanSend checks if data can be sent.
func (s *Session) CanSend() bool {
	if s.onData == nil {
		// publisherReady is intentionally not checked: KCP buffers outbound
		// data and retransmits if WriteSample fails while the publisher PC is
		// still connecting. Blocking on publisherReady causes handshake welcome
		// and tunnel stream acks to time out before the publisher PC is up.
		return !s.closed.Load() && s.subscriberReady.Load()
	}
	if s.dc == nil || s.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return false
	}
	return len(s.sendQueue) < defaultSendQueueCapHard
}

// AddVideoTrack adds a video track to the publisher peer connection.
func (s *Session) AddVideoTrack(track webrtc.TrackLocal) error {
	s.videoTrackMu.Lock()
	s.videoTracks = append(s.videoTracks, track)
	s.videoTrackMu.Unlock()

	if s.pcPub == nil {
		return nil
	}
	if _, err := s.pcPub.AddTrack(track); err != nil {
		return fmt.Errorf("failed to add track: %w", err)
	}
	return nil
}

// SetVideoTrackHandler registers a callback for remote video tracks.
func (s *Session) SetVideoTrackHandler(cb func(*webrtc.TrackRemote, *webrtc.RTPReceiver)) {
	s.videoTrackMu.Lock()
	defer s.videoTrackMu.Unlock()
	s.onVideoTrack = cb
}

func (s *Session) hasLocalVideoTracks() bool {
	s.videoTrackMu.RLock()
	defer s.videoTrackMu.RUnlock()
	return len(s.videoTracks) > 0
}

func (s *Session) videoTrackHandler() func(*webrtc.TrackRemote, *webrtc.RTPReceiver) {
	s.videoTrackMu.RLock()
	defer s.videoTrackMu.RUnlock()
	return s.onVideoTrack
}

func (s *Session) attachPendingVideoTracks() error {
	s.videoTrackMu.RLock()
	defer s.videoTrackMu.RUnlock()

	for _, track := range s.videoTracks {
		sender, err := s.pcPub.AddTrack(track)
		if err != nil {
			return fmt.Errorf("add video track: %w", err)
		}
		s.drainPublisherRTCP(sender)
	}
	return nil
}

// drainPublisherRTCP reads (and discards) RTCP feedback the SFU sends for our
// published track. The read is required so the interceptor chain keeps
// processing incoming RTCP; without an active reader it stalls.
func (s *Session) drainPublisherRTCP(sender *webrtc.RTPSender) {
	if sender == nil {
		return
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	}()
}

func closeSignal(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func init() { //nolint:gochecknoinits // engine registration is the canonical Go pattern for plugins
	engine.Register("goolom", New)
}
