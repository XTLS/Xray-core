// Package vp8channel disguises a KCP-based byte transport as a stream of
// valid VP8 keyframes so SFUs that validate bitstream conformance let the
// payload through. The package owns its own KCP framing; the per-message
// fragment/ack machinery used by videochannel/seichannel is unnecessary
// here because KCP already provides ordered, reliable delivery.
package vp8channel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	enginebuiltin "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/builtin"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport/common"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	defaultMaxPayloadSize = 60 * 1024
	defaultConnectTimeout = 60 * time.Second
	rtpBufSize            = 65536
	// outboundQueueSize bounds KCP packets waiting for the paced writer. Sized
	// to a couple of send windows so KCP's flush never blocks (a blocked
	// WriteTo would stall KCP's update loop and delay ACKs); the paced writer
	// keeps it drained so this depth is headroom, not standing latency.
	outboundQueueSize = 1536
	// controlOutboundQueueSize is the queue for the control-plane KCP.
	// Control messages are tiny (ping/pong JSON frames), so a small queue
	// suffices. We keep it separate from bulk data to guarantee forward
	// progress even when the data outbound queue is saturated.
	controlOutboundQueueSize = 2048 // sized for ~20s publisher reconnect window at 20ms tick
	inboundQueueSize         = 4096
	canSendHighWatermark     = 90 // percent
	keepaliveIdlePeriod      = 100 * time.Millisecond
	// defaultPeerRestartGrace is how long the latched peer must be silent
	// before a frame from a different epoch is read as a server restart. The
	// server emits a decodable keepalive every ~2s, so a few missed beats is
	// a confident "the latched peer is gone and a fresh one took its place"
	// signal while staying clear of normal SFU jitter. See issue #105.
	defaultPeerRestartGrace = 6 * time.Second
)

var (
	// ErrVideoTrackUnsupported is returned when a carrier cannot expose video tracks.
	ErrVideoTrackUnsupported = errors.New("carrier does not support video tracks")
	// ErrTransportClosed is returned when operations are attempted on a closed transport.
	ErrTransportClosed = errors.New("vp8channel transport closed")
)

var vp8Keepalive = []byte{ //nolint:gochecknoglobals // package-level state intentional
	0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
	0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
	0x99, 0x84, 0x88, 0xfc,
}

// KCP data frames are disguised as valid VP8 frames so Telemost SFU lets them
// through. The SFU validates the VP8 bitstream and drops frames that don't
// look like real VP8 - so we prepend the keepalive keyframe and append our
// header + payload after it. Wire layout:
//
//	[0..20]    = vp8Keepalive (valid VP8 keyframe, passes SFU inspection)
//	[20..24]   = binding token derived from client-id (big-endian uint32)
//	[24..28]   = sender's session epoch (src, big-endian uint32)
//	[28..32]   = destination epoch (dst, big-endian uint32; 0 = broadcast)
//	[32..36]   = CRC32(token || src || dst)
//	[36..]     = raw KCP packet bytes
//
// The dst field lets the server address downlink to one specific client even
// though the SFU forwards every frame to every participant: a receiver drops
// any frame whose dst is non-zero and not its own epoch. dst==0 is a broadcast
// used before the sender has learned the receiver's epoch (CLIENT_HELLO and
// the server's pre-latch frames). This mirrors the src+dst scheme the jitsi
// engine already uses (internal/engine/jitsi).
const (
	tokenOff    = 20
	srcOff      = 24
	dstOff      = 28
	crcOff      = 32
	epochHdrLen = 36
	// controlEpochFlag marks an epoch as belonging to the control-plane
	// KCP session. The high bit of the epoch uint32 is reserved for this
	// purpose; data-plane epochs are generated with the high bit clear.
	controlEpochFlag uint32 = 0x80000000
)

var kcpBatchMagic = [4]byte{'O', 'L', 'K', 'B'} //nolint:gochecknoglobals // wire marker

// videoSession is the subset of engine.Session + engine.VideoTrackCapable
// the vp8channel transport relies on. It necessarily mirrors the engine's
// lifecycle + video contract, so the method count exceeds the default bloat
// threshold by design.
//
//nolint:interfacebloat // mirrors the engine.Session + video contract
type videoSession interface {
	Connect(ctx context.Context) error
	Close() error
	SetReconnectCallback(cb func())
	SetShouldReconnect(fn func() bool)
	SetEndedCallback(cb func(string))
	WatchConnection(ctx context.Context)
	CanSend() bool
	// SubscriberCanSend returns true when the subscriber PC is connected,
	// even if the publisher PC has not yet completed negotiation. Used by
	// the control-plane path so that handshake welcome is never blocked
	// behind publisher negotiation.
	SubscriberCanSend() bool
	Reconnect(reason string)
	AddTrack(track webrtc.TrackLocal) error
	SetTrackHandler(cb func(*webrtc.TrackRemote, *webrtc.RTPReceiver))
}

type streamTransport struct {
	stream videoSession
	track  *webrtc.TrackLocalStaticSample
	// writeMu serializes all track.WriteSample calls. pion's WriteSample is
	// not safe for concurrent use (see writeSampleLocked); the server writes
	// bulk data from per-peer pumps while writerLoop writes control frames
	// and keepalives, so both paths must funnel through this lock.
	writeMu sync.Mutex
	// sampleWriter, when set, replaces the real track.WriteSample call.
	// Tests inject a writer here to observe the exact byte stream that
	// reaches the track and to assert that writeSampleLocked serializes
	// concurrent callers. Always invoked under writeMu.
	sampleWriter func([]byte) bool
	onData       func([]byte)
	onPeerData   func(peerID string, data []byte)
	// onControlData is called with every reassembled message from the
	// control-plane KCP session.
	onControlData func([]byte)
	outbound      chan []byte
	// controlOutbound is the dedicated outbound queue for the control KCP.
	// Frames here are drained with priority before bulk data frames so that
	// handshake / liveness messages never wait behind large data writes.
	controlOutbound chan []byte
	closeCh         chan struct{}
	writerDone      chan struct{}
	closed          atomic.Bool
	writerUp        atomic.Bool
	writerOnce      sync.Once
	kcpOnce         sync.Once
	controlKCPOnce  sync.Once
	frameInterval   time.Duration
	batchSize       int

	// localEpoch is stamped into every outgoing VP8 frame. Explicit
	// upper-layer resets rotate it so the peer can reset its KCP state too.
	// Peer-triggered resets keep it stable to avoid reset ping-pong.
	bindingToken uint32
	epochMu      sync.RWMutex
	localEpoch   uint32
	peerEpoch    atomic.Uint32

	// lastPeerFrameNano stamps the wall-clock time of the most recent frame
	// from the latched peer epoch. peerRestarting guards the carrier rebuild
	// from firing more than once per restart. peerRestartGrace is how long the
	// latched peer must be silent before a frame from a different epoch is read
	// as a restarted server rather than unrelated room noise. A restarted
	// server rejoins the SFU with a fresh epoch and broadcasts decodable
	// keepalives on it; spotting that lets us rebuild the carrier in seconds
	// instead of waiting out the relaxed control-liveness window (~70s).
	// See issue #105.
	lastPeerFrameNano atomic.Int64
	peerRestarting    atomic.Bool
	peerRestartGrace  time.Duration

	kcp   *kcpRuntime
	kcpMu sync.RWMutex
	// controlKCP is the isolated KCP session for the control plane.
	controlKCP      *kcpRuntime
	controlKCPMu    sync.RWMutex
	controlOnDataMu sync.RWMutex // guards onControlData reads/writes
	reconnectMu     sync.Mutex
	reconnectFn     func()
	peerConfirmed   atomic.Bool

	// Multi-peer support: when onPeerData is set, each remote epoch gets
	// its own KCP runtime and data is routed via onPeerData(peerID, ...).
	peersMu sync.RWMutex
	peers   map[uint32]*kcpRuntime // data epoch → KCP runtime
	peerOut map[uint32]chan []byte // data epoch → outbound queue

	// Per-peer control plane: keyed by data epoch (= controlEpoch &^ controlEpochFlag).
	// Each entry owns its own KCP session so multiple clients get independent
	// handshake/liveness streams. Guarded by ctrlPeersMu.
	ctrlPeersMu sync.RWMutex
	ctrlPeers   map[uint32]*peerControlKCP // data epoch → per-peer control KCP

	// onPeerControlData is called when a control frame arrives for a specific
	// peer. Set by SetControlOnPeerData.
	onPeerControlData func(peerID string, data []byte)

	// Connect eagerly starts both KCPs; the control KCP uses the current
	// controlEpochValue() which is now derived live from localEpoch.
	_ struct{} // zero-size sentinel — keeps the struct layout stable
}

// peerControlKCP holds the isolated KCP session for one remote peer's control
// plane. The server creates one per data epoch; each gets its own KCP session
// so that multiple clients can handshake and ping/pong independently.
type peerControlKCP struct {
	kcp *kcpRuntime
	out chan []byte
}

// New creates a vp8channel transport backed by a carrier engine.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	opts, err := optionsFrom(cfg)
	if err != nil {
		return nil, err
	}

	session, err := enginebuiltin.Open(ctx, cfg.Carrier, enginebuiltin.Config{
		RoomURL:   cfg.RoomURL,
		Name:      cfg.Name,
		OnData:    nil,
		DNSServer: cfg.DNSServer,
		ProxyAddr: cfg.ProxyAddr,
		ProxyPort: cfg.ProxyPort,
		Engine:    cfg.Engine,
		URL:       cfg.URL,
		Token:     cfg.Token,
		AuthToken: cfg.AuthToken,
	})
	if err != nil {
		return nil, fmt.Errorf("open engine session: %w", err)
	}

	vt, ok := session.(engine.VideoTrackCapable)
	if !ok || !session.Capabilities().VideoTrack {
		_ = session.Close()
		return nil, ErrVideoTrackUnsupported
	}
	stream := &engineVideoSession{session: session, vt: vt}

	// Stream/track IDs must be unique per peer - Jitsi rejects session-accept
	// when msid collides with another participant in the conference.
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		"vp8channel-"+common.RandomID(),
		"olcrtc-"+common.RandomID(),
	)
	if err != nil {
		return nil, fmt.Errorf("create local video track: %w", err)
	}

	tr := newStreamTransport(stream, track, cfg, opts)

	if err := stream.AddTrack(track); err != nil {
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	stream.SetTrackHandler(tr.handleRemoteTrack)

	return tr, nil
}

func newStreamTransport(
	stream *engineVideoSession,
	track *webrtc.TrackLocalStaticSample,
	cfg transport.Config,
	opts Options,
) *streamTransport {
	fps := opts.FPS
	batchSize := opts.BatchSize
	if fps <= 0 {
		fps = defaultFPS
	}
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	tr := &streamTransport{
		stream:          stream,
		track:           track,
		onData:          cfg.OnData,
		onPeerData:      cfg.OnPeerData,
		outbound:        make(chan []byte, outboundQueueSize),
		controlOutbound: make(chan []byte, controlOutboundQueueSize),
		closeCh:         make(chan struct{}),
		writerDone:      make(chan struct{}),
		frameInterval:   time.Second / time.Duration(fps),
		batchSize:       batchSize,
		bindingToken:    bindingToken(cfg.RoomURL),
		localEpoch:      randomEpoch(),
		peers:            make(map[uint32]*kcpRuntime),
		peerOut:          make(map[uint32]chan []byte),
		ctrlPeers:        make(map[uint32]*peerControlKCP),
		peerRestartGrace: defaultPeerRestartGrace,
	}

	// In single-peer mode, confirm the peer epoch on first successful KCP
	// delivery. This ensures we latch on the server (which completes
	// handshake) rather than another client whose frames arrive first.
	if cfg.OnData != nil && cfg.OnPeerData == nil {
		inner := cfg.OnData
		tr.onData = func(data []byte) {
			if !tr.peerConfirmed.Swap(true) {
				epoch := tr.peerEpoch.Load()
				logger.Infof("vp8channel: peer confirmed epoch=0x%08x", epoch)
			}
			inner(data)
		}
	} else {
		tr.onData = cfg.OnData
	}

	return tr
}

func (p *streamTransport) Connect(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := p.stream.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	// Start data KCP eagerly so Send/CanSend work immediately after Connect.
	// Without this, the handshake round-trip that runs right after Connect
	// would deadlock: muxconn.Write spins on CanSend (which checks kcp!=nil)
	// and KCP was only started lazily on the first incoming peer frame.
	p.kcpOnce.Do(func() {
		rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
		if err != nil {
			logger.Infof("vp8channel: startKCP failed: %v", err)
			return
		}
		p.kcpMu.Lock()
		p.kcp = rt
		p.kcpMu.Unlock()
		logger.Infof("vp8channel: KCP started localEpoch=0x%08x", p.localEpochValue())
	})

	// Start control KCP on its own isolated session. Control messages are tiny
	// (ping/pong JSON) and must never be blocked behind bulk data segments.
	// We pass a wrapper callback that always reads the current onControlData
	// field under the mutex, so SetControlOnData can update it without
	// restarting the KCP session.
	p.controlKCPOnce.Do(func() {
		controlCb := func(data []byte) {
			p.controlOnDataMu.RLock()
			cb := p.onControlData
			p.controlOnDataMu.RUnlock()
			if cb != nil {
				cb(data)
			}
		}
		chdr := p.controlEpochHeader()
		rt, err := startKCP(p.controlOutbound, controlCb, chdr)
		if err != nil {
			logger.Infof("vp8channel: startControlKCP failed: %v", err)
			return
		}
		p.controlKCPMu.Lock()
		p.controlKCP = rt
		p.controlKCPMu.Unlock()
		logger.Infof("vp8channel: control KCP started epoch=0x%08x", p.controlEpochValue())
	})

	p.writerOnce.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()
	})

	return nil
}

// epochHeader returns the 5-byte VP8-frame header used to tag every KCP
// packet sent in the current local session.
func (p *streamTransport) epochHeader() [epochHdrLen]byte {
	p.epochMu.RLock()
	epoch := p.localEpoch
	p.epochMu.RUnlock()
	return buildEpochHeader(p.bindingToken, epoch)
}

// controlEpochValue derives the control-plane epoch live from the current
// data epoch. Control epoch = localEpoch | controlEpochFlag. The high bit
// is set so the receiver can distinguish control frames from bulk data frames
// on the same RTP stream, and the server can correlate a client's data and
// control planes by arithmetic (controlEpoch &^ controlEpochFlag == dataEpoch).
// This must stay live (not latched) so that data epoch rotations on reconnect
// are visible to the server; with a latched control epoch the server could no
// longer correlate a new data epoch to the same client's control stream.
func (p *streamTransport) controlEpochValue() uint32 {
	return p.localEpochValue() | controlEpochFlag
}

// controlEpochHeader builds the epoch header for the control-plane track.
// The control epoch has the high bit set so the receiver can distinguish
// control frames from bulk data frames arriving on the same RTP stream.
func (p *streamTransport) controlEpochHeader() [epochHdrLen]byte {
	return buildEpochHeader(p.bindingToken, p.controlEpochValue())
}

func buildEpochHeader(token, src uint32) [epochHdrLen]byte {
	return buildEpochHeaderTo(token, src, 0)
}

// buildEpochHeaderTo builds a frame header addressed to a specific destination
// epoch. dst==0 means broadcast (every participant accepts it).
func buildEpochHeaderTo(token, src, dst uint32) [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	copy(hdr[:], vp8Keepalive)
	binary.BigEndian.PutUint32(hdr[tokenOff:srcOff], token)
	binary.BigEndian.PutUint32(hdr[srcOff:dstOff], src)
	binary.BigEndian.PutUint32(hdr[dstOff:crcOff], dst)
	binary.BigEndian.PutUint32(hdr[crcOff:epochHdrLen], epochCRC(token, src, dst))
	return hdr
}

func (p *streamTransport) rotateEpochHeader() [epochHdrLen]byte {
	p.epochMu.Lock()
	for {
		next := randomEpoch()
		if next != p.localEpoch {
			p.localEpoch = next
			break
		}
	}
	epoch := p.localEpoch
	p.epochMu.Unlock()
	return buildEpochHeader(p.bindingToken, epoch)
}

func (p *streamTransport) localEpochValue() uint32 {
	p.epochMu.RLock()
	defer p.epochMu.RUnlock()
	return p.localEpoch
}

func epochCRC(token, src, dst uint32) uint32 {
	var buf [12]byte
	binary.BigEndian.PutUint32(buf[0:4], token)
	binary.BigEndian.PutUint32(buf[4:8], src)
	binary.BigEndian.PutUint32(buf[8:12], dst)
	return crc32.ChecksumIEEE(buf[:])
}

// parseEpochHeader returns (token, src, dst, ok). ok is false when the frame is
// too short or the CRC does not validate.
func parseEpochHeader(frame []byte) (uint32, uint32, uint32, bool) {
	if len(frame) < epochHdrLen {
		return 0, 0, 0, false
	}
	token := binary.BigEndian.Uint32(frame[tokenOff:srcOff])
	src := binary.BigEndian.Uint32(frame[srcOff:dstOff])
	dst := binary.BigEndian.Uint32(frame[dstOff:crcOff])
	gotCRC := binary.BigEndian.Uint32(frame[crcOff:epochHdrLen])
	return token, src, dst, gotCRC == epochCRC(token, src, dst)
}

func bindingToken(clientID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(clientID))
	token := h.Sum32()
	if token == 0 {
		token = 1
	}
	return token
}

func randomEpoch() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux essentially never fails; fall back to a
		// time-derived value rather than panic.
		//nolint:gosec // G115: bounded conversion verified by surrounding logic
		e := uint32(time.Now().UnixNano()) & ^controlEpochFlag
		if e == 0 {
			e = 1
		}
		return e
	}
	// Mask off the high bit: data epochs must not collide with control epochs.
	e := binary.BigEndian.Uint32(b[:]) & ^controlEpochFlag
	if e == 0 {
		e = 1
	}
	return e
}

func (p *streamTransport) Send(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}

	return rt.send(data)
}

// SendTo transmits data to a specific peer identified by its epoch hex string.
func (p *streamTransport) SendTo(peerID string, data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return fmt.Errorf("vp8channel: invalid peerID %q: %w", peerID, err)
	}
	p.peersMu.RLock()
	rt := p.peers[epoch]
	p.peersMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}
	return rt.send(data)
}

// SupportsPeerRouting reports whether this transport can address individual peers.
func (p *streamTransport) SupportsPeerRouting() bool {
	return p.onPeerData != nil
}

func (p *streamTransport) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)

		p.kcpMu.RLock()
		rt := p.kcp
		p.kcpMu.RUnlock()
		if rt != nil {
			rt.close()
		}

		p.controlKCPMu.RLock()
		crt := p.controlKCP
		p.controlKCPMu.RUnlock()
		if crt != nil {
			crt.close()
		}

		p.peersMu.Lock()
		for _, prt := range p.peers {
			prt.close()
		}
		p.peers = make(map[uint32]*kcpRuntime)
		p.peerOut = make(map[uint32]chan []byte)
		p.peersMu.Unlock()

		p.ctrlPeersMu.Lock()
		for _, pcp := range p.ctrlPeers {
			pcp.kcp.close()
		}
		p.ctrlPeers = make(map[uint32]*peerControlKCP)
		p.ctrlPeersMu.Unlock()

		if p.writerUp.Load() {
			<-p.writerDone
		}
		if err := p.stream.Close(); err != nil {
			return fmt.Errorf("close stream: %w", err)
		}
	}
	return nil
}

func (p *streamTransport) drainOutbound() {
	for {
		select {
		case <-p.outbound:
		default:
			return
		}
	}
}

func (p *streamTransport) drainControlOutbound() {
	for {
		select {
		case <-p.controlOutbound:
		default:
			return
		}
	}
}

// ResetPeer drops queued KCP traffic and starts a fresh KCP state machine while
// keeping the carrier connection alive. The client/server liveness layer calls
// this before rebuilding smux so replacement handshakes are not parsed behind
// stale bytes from streams that were active when the old session died.
func (p *streamTransport) ResetPeer() {
	p.peerConfirmed.Store(false)
	p.peerEpoch.Store(0)
	// Rotate data epoch; controlEpochValue() derives live from the new data
	// epoch so the control header automatically follows.
	newHdr := p.rotateEpochHeader()
	p.restartKCP(newHdr)
	p.restartControlKCPWithHeader(p.controlEpochHeader())
}

// Reconnect forwards to the underlying engine session.
func (p *streamTransport) Reconnect(reason string) {
	p.stream.Reconnect(reason)
}

func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.reconnectMu.Lock()
	p.reconnectFn = cb
	p.reconnectMu.Unlock()
	p.stream.SetReconnectCallback(func() {
		// Rotate the data epoch and restart both KCPs. controlEpochValue()
		// derives live from the new data epoch so the control header follows
		// automatically — the peer re-correlates data+control by arithmetic.
		p.peerConfirmed.Store(false)
		p.peerEpoch.Store(0)
		p.restartKCP(p.rotateEpochHeader())
		p.restartControlKCPWithHeader(p.controlEpochHeader())
		if cb != nil {
			cb()
		}
	})
}

func (p *streamTransport) SetShouldReconnect(fn func() bool) {
	p.stream.SetShouldReconnect(fn)
}

func (p *streamTransport) SetEndedCallback(cb func(string)) {
	p.stream.SetEndedCallback(cb)
}

func (p *streamTransport) WatchConnection(ctx context.Context) {
	p.stream.WatchConnection(ctx)
}

// WaitForPeer blocks until the remote peer has been observed (first epoch
// frame received), or ctx is cancelled.
// Implements transport.PeerReadyTransport.
func (p *streamTransport) WaitForPeer(ctx context.Context) error {
	const pollInterval = 50 * time.Millisecond
	for {
		if p.peerEpoch.Load() != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for peer: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

func (p *streamTransport) CanSend() bool {
	if p.closed.Load() {
		return false
	}
	p.kcpMu.RLock()
	hasKCP := p.kcp != nil
	p.kcpMu.RUnlock()
	return hasKCP && p.stream.CanSend() &&
		len(p.outbound) < cap(p.outbound)*canSendHighWatermark/100
}

// ControlCanSend reports whether the control-plane is ready to send.
// Unlike CanSend, it does not require the publisher PC to be ready —
// control frames (handshake welcome, ping/pong) must go through even
// before the publisher negotiation completes.
func (p *streamTransport) ControlCanSend() bool {
	if p.closed.Load() {
		return false
	}
	p.controlKCPMu.RLock()
	hasKCP := p.controlKCP != nil
	p.controlKCPMu.RUnlock()
	// Only require subscriber to be ready — the control path does not need
	// the publisher PC; writerLoop handles WriteSample retries.
	return hasKCP && p.stream.SubscriberCanSend()
}

// Features advertises reliable+ordered semantics now that KCP guarantees
// in-order delivery with retransmits. The upper layer (mux/curl tunnel)
// can rely on these properties end-to-end.
func (p *streamTransport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  defaultMaxPayloadSize,
	}
}

// writerState holds the per-loop bookkeeping for writerLoop, extracted so the
// loop body stays within cognitive-complexity limits.
type writerState struct {
	p                   *streamTransport
	keepaliveEvery      int
	idleTicks           int
	forceKeepaliveEvery int
	ticksSinceKeepalive int
	// pendingControl holds a control frame that failed WriteSample and must be
	// retried on the next tick before consuming more frames.
	pendingControl []byte
}

func (w *writerState) writeSample(data []byte) bool {
	return w.p.writeSampleLocked(data)
}

// writeSampleLocked serializes every WriteSample call on the shared video
// track behind a single mutex. pion's TrackLocalStaticSample.WriteSample is
// NOT safe for concurrent use: it packetizes under its own lock but then
// releases that lock before pushing the resulting RTP packets onto the wire.
// Two concurrent callers therefore each reserve a contiguous block of RTP
// sequence numbers and then race to emit their packets, interleaving them on
// the wire. The receiver's VP8 reassembler enforces strict sequence
// contiguity, so any interleaved frame is discarded - which is exactly the
// server->client bulk-data stall in issue #95 (the server runs a per-peer
// peerWriterPump for data plus writerLoop for control/keepalive, both hitting
// this track at once). Funneling all writes through this mutex makes each
// sample's packetize+send atomic and keeps sequence numbers monotonic.
func (p *streamTransport) writeSampleLocked(data []byte) bool {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.sampleWriter != nil {
		return p.sampleWriter(data)
	}
	return p.track.WriteSample(media.Sample{
		Data:     data,
		Duration: p.frameInterval,
	}) == nil
}

// forceKeepalive emits a clean, fully-decodable VP8 keepalive keyframe at a
// steady cadence even while bulk data is flowing. During a sustained bulk
// transfer every emitted "frame" is the epoch header plus opaque KCP bytes,
// which never forms a decodable VP8 keyframe. The SFU asks for a keyframe (PLI)
// and, receiving none within its decode-timeout (~40 s), stops forwarding the
// track to subscribers. The periodic bare keyframe keeps the SFU's decoder
// satisfied.
func (w *writerState) forceKeepalive() {
	w.ticksSinceKeepalive++
	if w.ticksSinceKeepalive >= w.forceKeepaliveEvery {
		w.ticksSinceKeepalive = 0
		hdr := w.p.epochHeader()
		_ = w.writeSample(hdr[:])
	}
}

// drainControl flushes all queued control frames. Returns false when a frame
// failed to send (stored in pendingControl for retry next tick).
func (w *writerState) drainControl() bool {
	if w.pendingControl != nil {
		if !w.writeSample(w.pendingControl) {
			return false
		}
		w.pendingControl = nil
	}
	for {
		select {
		case frame := <-w.p.controlOutbound:
			w.idleTicks = 0
			if !w.writeSample(frame) {
				w.pendingControl = frame
				return false
			}
		default:
			return true
		}
	}
}

// drainData sends one batched data frame, or a keepalive when idle.
func (w *writerState) drainData() {
	select {
	case frame := <-w.p.outbound:
		sample := w.p.batchSample(frame)
		w.idleTicks = 0
		_ = w.writeSample(sample)
	default:
		w.idleTicks++
		if w.idleTicks >= w.keepaliveEvery {
			w.idleTicks = 0
			hdr := w.p.epochHeader()
			_ = w.writeSample(hdr[:])
		}
	}
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	ticker := time.NewTicker(p.frameInterval)
	defer ticker.Stop()

	w := &writerState{
		p:                   p,
		keepaliveEvery:      max(int(keepaliveIdlePeriod/p.frameInterval), 1),
		forceKeepaliveEvery: max(int((2*time.Second)/p.frameInterval), 1),
	}

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			// Priority 0: keep a decodable keyframe flowing for the SFU.
			w.forceKeepalive()
			// Priority 1+2: drain all control frames before any bulk data.
			if !w.drainControl() {
				continue // a control frame is still failing; retry next tick
			}
			// Priority 3: drain a batched data frame (or send keepalive).
			w.drainData()
		}
	}
}

func (p *streamTransport) batchSample(first []byte) []byte {
	return p.batchSampleFrom(p.outbound, first)
}

// batchSampleFrom coalesces up to batchSize KCP frames drained from src into a
// single VP8 sample, bounded by defaultMaxPayloadSize. The shared writerLoop
// drains the single-peer outbound queue; per-peer pumps drain their own queue
// through the same batching so the server->client path is built identically to
// the client.
func (p *streamTransport) batchSampleFrom(src <-chan []byte, first []byte) []byte {
	if len(first) <= epochHdrLen || p.batchSize <= 1 {
		return first
	}

	sample := make([]byte, 0, defaultMaxPayloadSize)
	sample = append(sample, first[:epochHdrLen]...)
	sample = append(sample, kcpBatchMagic[:]...)
	sample = appendBatchPacket(sample, first[epochHdrLen:])

	for packets := 1; packets < p.batchSize; packets++ {
		select {
		case frame := <-src:
			if len(frame) <= epochHdrLen {
				continue
			}
			payload := frame[epochHdrLen:]
			if len(sample)+2+len(payload) > defaultMaxPayloadSize {
				return sample
			}
			sample = appendBatchPacket(sample, payload)
		default:
			return sample
		}
	}
	return sample
}

func appendBatchPacket(dst, packet []byte) []byte {
	if len(packet) > 0xffff {
		return dst
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packet))) //nolint:gosec // bounded above
	dst = append(dst, lenBuf[:]...)
	return append(dst, packet...)
}

func (p *streamTransport) restartKCP(epochHdr [epochHdrLen]byte) {
	p.drainOutbound()
	p.kcpMu.Lock()
	old := p.kcp
	p.kcp = nil
	p.kcpMu.Unlock()
	if old != nil {
		old.close()
	}
	rt, err := startKCP(p.outbound, p.onData, epochHdr)
	if err != nil {
		return
	}
	p.kcpMu.Lock()
	p.kcp = rt
	p.kcpMu.Unlock()
}

// restartControlKCPWithHeader restarts the control KCP with a specific epoch header,
// used to preserve the control epoch across carrier reconnects.
func (p *streamTransport) restartControlKCPWithHeader(hdr [epochHdrLen]byte) {
	p.drainControlOutbound()
	p.controlKCPMu.Lock()
	old := p.controlKCP
	p.controlKCP = nil
	p.controlKCPMu.Unlock()
	if old != nil {
		old.close()
	}
	controlCb := func(data []byte) {
		p.controlOnDataMu.RLock()
		cb := p.onControlData
		p.controlOnDataMu.RUnlock()
		if cb != nil {
			cb(data)
		}
	}
	rt, err := startKCP(p.controlOutbound, controlCb, hdr)
	if err != nil {
		return
	}
	p.controlKCPMu.Lock()
	p.controlKCP = rt
	p.controlKCPMu.Unlock()
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		go p.drainTrack(track)
		return
	}

	// We don't reset KCP here. Peer restarts are detected by the epoch
	// header on incoming frames, which works even when the SFU keeps
	// forwarding the same track across our restarts.
	go p.readVP8Track(track)
}

func (p *streamTransport) drainTrack(track *webrtc.TrackRemote) {
	buf := make([]byte, rtpBufSize)
	for {
		if _, _, err := track.Read(buf); err != nil {
			return
		}
	}
}

// reorderWindow bounds how many out-of-order RTP packets the reorder buffer
// holds while waiting for a gap to fill. Real SFUs reorder within a handful of
// packets; once this many newer packets pile up behind a hole, the missing
// sequence is treated as genuinely lost and we advance, so a truly dropped
// packet cannot stall delivery indefinitely.
const reorderWindow = 256

// seqLess reports whether RTP sequence a precedes b using wrap-around aware
// comparison (RFC 1982 serial arithmetic on uint16).
func seqLess(a, b uint16) bool {
	// bit15 of the wrap-around difference is the serial sign bit: set means a
	// precedes b. Avoids a signed conversion gosec flags as overflow.
	return (a-b)&0x8000 != 0
}

// reorderBuffer restores RTP sequence order before frame assembly. The SFU may
// deliver packets out of order or drop them; feeding that stream straight into
// the strict contiguity check in processRTPPacket made every reorder look like
// loss and discarded whole frames (issue #95: ~80-90% of VP8 frames dropped on
// a live SFU). Buffering by sequence number and draining in order means only
// genuine loss produces a gap.
type reorderBuffer struct {
	pkts    map[uint16]*rtp.Packet
	nextSeq uint16
	started bool
}

func newReorderBuffer() *reorderBuffer {
	return &reorderBuffer{pkts: make(map[uint16]*rtp.Packet, reorderWindow)}
}

// push adds pkt and returns any packets now deliverable in strict sequence
// order. The caller reuses its read buffer across packets, so the payload is
// copied before buffering.
func (b *reorderBuffer) push(pkt *rtp.Packet) []*rtp.Packet {
	if !b.started {
		b.started = true
		b.nextSeq = pkt.SequenceNumber
	}
	// Drop packets older than our current position: already delivered, or
	// skipped past as lost.
	if seqLess(pkt.SequenceNumber, b.nextSeq) {
		return nil
	}
	cp := &rtp.Packet{Header: pkt.Header}
	cp.Payload = append([]byte(nil), pkt.Payload...)
	b.pkts[pkt.SequenceNumber] = cp

	// Holding a full window behind a hole means the head sequence is
	// genuinely lost: skip forward to the oldest buffered packet.
	if len(b.pkts) > reorderWindow {
		b.skipToOldest()
	}
	return b.drain()
}

// drain pops contiguous packets starting at nextSeq.
func (b *reorderBuffer) drain() []*rtp.Packet {
	var out []*rtp.Packet
	for {
		pkt, ok := b.pkts[b.nextSeq]
		if !ok {
			return out
		}
		out = append(out, pkt)
		delete(b.pkts, b.nextSeq)
		b.nextSeq++
	}
}

// skipToOldest advances nextSeq to the lowest buffered sequence, abandoning a
// lost packet so drain can make progress.
func (b *reorderBuffer) skipToOldest() {
	first := true
	var oldest uint16
	for seq := range b.pkts {
		if first || seqLess(seq, oldest) {
			oldest = seq
			first = false
		}
	}
	b.nextSeq = oldest
}

type vp8FrameState struct {
	vp8Pkt      codecs.VP8Packet
	frameBuf    []byte
	lastSeq     uint16
	haveLastSeq bool
	frameValid  bool
}

// processRTPPacket returns a complete VP8 frame payload when fully assembled,
// nil otherwise. Detects packet loss/reordering to avoid silently corrupting
// fragmented VP8 frames.
func (s *vp8FrameState) processRTPPacket(pkt *rtp.Packet) []byte {
	if s.haveLastSeq && pkt.SequenceNumber != s.lastSeq+1 {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
	}
	s.lastSeq = pkt.SequenceNumber
	s.haveLastSeq = true

	vp8Payload, err := s.vp8Pkt.Unmarshal(pkt.Payload)
	if err != nil {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
		return nil
	}

	if s.vp8Pkt.S == 1 {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = true
	}

	if !s.frameValid {
		return nil
	}

	s.frameBuf = append(s.frameBuf, vp8Payload...)

	if !pkt.Marker {
		return nil
	}

	defer func() {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = false
	}()

	if len(s.frameBuf) >= epochHdrLen {
		frame := make([]byte, len(s.frameBuf))
		copy(frame, s.frameBuf)
		return frame
	}
	return nil
}

func (p *streamTransport) readVP8Track(track *webrtc.TrackRemote) {
	var state vp8FrameState
	reorder := newReorderBuffer()
	buf := make([]byte, rtpBufSize)
	var rtpCount, frameCount int

	for {
		n, _, err := track.Read(buf)
		if err != nil {
			logger.Infof("vp8channel: readVP8Track closed track=%s rtp=%d frames=%d err=%v",
				track.ID(), rtpCount, frameCount, err)
			return
		}
		rtpCount++

		pkt := &rtp.Packet{}
		if pkt.Unmarshal(buf[:n]) != nil {
			continue
		}

		// Restore sequence order before assembly so SFU reordering is not
		// mistaken for loss.
		for _, ordered := range reorder.push(pkt) {
			frame := state.processRTPPacket(ordered)
			if frame == nil {
				continue
			}
			frameCount++
			p.handleIncomingFrame(frame)
		}
	}
}

func (p *streamTransport) handleFirstPeer(peerEpoch uint32) {
	p.peerEpoch.Store(peerEpoch)
	p.peerConfirmed.Store(true)
	// Arm the restart watchdog against this fresh latch and clear any pending
	// restart flag so a later silence can re-trigger detection (issue #105).
	p.lastPeerFrameNano.Store(time.Now().UnixNano())
	p.peerRestarting.Store(false)
	// Re-point our data KCP at the server so subsequent uplink frames are
	// addressed (dst=serverEpoch) instead of broadcast. The SFU forwards
	// every frame to every participant, so without a dst the server cannot
	// tell which client a frame belongs to and other clients would ingest
	// our KCP packets (issue #95 multi-client cross-talk).
	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt != nil {
		rt.setHeader(buildEpochHeaderTo(p.bindingToken, p.localEpochValue(), peerEpoch))
	}
	logger.Infof("vp8channel: peer latched epoch=0x%08x", peerEpoch)
}

// acceptsDst reports whether a frame addressed to dst is for us. dst==0 is a
// broadcast (accepted by everyone, used before the sender has learned our
// epoch). Otherwise the frame must target either our data epoch or our
// control epoch (data|controlEpochFlag).
func (p *streamTransport) acceptsDst(dst uint32) bool {
	if dst == 0 {
		return true
	}
	le := p.localEpochValue()
	return dst == le || dst == (le|controlEpochFlag)
}

// handleIncomingFrame parses the epoch header and delivers KCP payload.
func (p *streamTransport) handleIncomingFrame(frame []byte) {
	frameToken, src, dst, ok := parseEpochHeader(frame)
	if !ok {
		logger.Debugf("vp8channel: incoming frame bad header len=%d", len(frame))
		return
	}
	if frameToken != p.bindingToken {
		logger.Debugf("vp8channel: incoming frame token mismatch got=0x%08x want=0x%08x", frameToken, p.bindingToken)
		return
	}
	kcpPayload := frame[epochHdrLen:]
	if src == p.localEpochValue() || src == (p.localEpochValue()|controlEpochFlag) {
		return // own loopback (data or control)
	}
	// Drop frames addressed to a different participant. dst==0 broadcasts are
	// always accepted (bootstrap before the sender learns our epoch).
	if !p.acceptsDst(dst) {
		return
	}

	// Control-plane frames have the high bit set in the src epoch field.
	// Route them to the control plane and never mix them with bulk data.
	if src&controlEpochFlag != 0 {
		p.handleControlFrame(src, dst, kcpPayload)
		return
	}

	// Multi-peer mode: route each epoch to its own KCP runtime.
	if p.onPeerData != nil {
		p.handlePeerFrame(src, kcpPayload)
		return
	}

	p.handleSinglePeerData(src, kcpPayload)
}

// handleSinglePeerData delivers a data frame in single-peer (client) mode. It
// latches the first peer epoch seen. When the latched peer has gone silent
// past peerRestartGrace and a frame from a different epoch arrives, that is
// read as a server restart (the server rejoins the SFU with a fresh epoch) and
// triggers a full carrier rebuild instead of waiting out the relaxed
// control-liveness window (issue #105).
func (p *streamTransport) handleSinglePeerData(src uint32, kcpPayload []byte) {
	switch {
	case !p.peerConfirmed.Load():
		p.handleFirstPeer(src)
	case src != p.peerEpoch.Load():
		p.maybePeerRestart(src)
		return
	default:
		p.lastPeerFrameNano.Store(time.Now().UnixNano())
	}

	if len(kcpPayload) == 0 {
		return
	}
	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt != nil {
		deliverKCPPayload(rt, kcpPayload)
	}
}

// maybePeerRestart reads a frame from a non-latched epoch as a server restart
// once the latched peer has been silent longer than peerRestartGrace. A live
// peer keeps the latch fresh by emitting a keepalive every ~2s, so a different
// epoch arriving after a silence gap means the old peer is gone and a fresh one
// (a restarted server) has taken its place.
//
// Recovery drives the full carrier rebuild via stream.Reconnect - the same
// path control-liveness loss uses - rather than a bare re-handshake over the
// stale carrier. The restarted server rejoined the SFU as a fresh participant,
// so re-handshaking on the old media path just times out; only a carrier
// rebuild re-establishes a path the new server answers on. The carrier's
// reconnect callback then rotates our epoch, resets the peer latch and drives
// a fresh handshake. Firing this on the epoch change recovers in seconds
// instead of waiting out the relaxed control-liveness window (~70s, issue
// #105). We rebuild exactly once per restart; the flag clears when the next
// peer latches in handleFirstPeer.
func (p *streamTransport) maybePeerRestart(src uint32) {
	if p.peerRestartGrace <= 0 {
		return
	}
	last := p.lastPeerFrameNano.Load()
	if last == 0 || time.Since(time.Unix(0, last)) < p.peerRestartGrace {
		return
	}
	if !p.peerRestarting.CompareAndSwap(false, true) {
		return // a rebuild is already in flight
	}
	logger.Infof("vp8channel: peer restart detected old=0x%08x new=0x%08x - rebuilding carrier",
		p.peerEpoch.Load(), src)
	go p.stream.Reconnect("peer restart")
}

// handleControlFrame routes a control-plane VP8 frame. In multi-peer mode
// (server) each data epoch gets its own per-peer control KCP created on demand.
// In single-peer mode (client) the shared singleton control KCP is used.
// src carries the peer's control epoch (high bit set), dst is our epoch (or 0
// for broadcast). Loopback echoes of our own frames are discarded by the
// caller (handleIncomingFrame) via the src == localControlEpoch check.
func (p *streamTransport) handleControlFrame(src, dst uint32, kcpPayload []byte) {
	if len(kcpPayload) == 0 {
		return // control keepalive, nothing to deliver
	}
	// Multi-peer mode: route by data epoch (src &^ controlEpochFlag).
	if p.onPeerData != nil {
		dataEpoch := src &^ controlEpochFlag
		pcp := p.getOrCreatePeerControlKCP(dataEpoch)
		if pcp != nil {
			deliverKCPPayload(pcp.kcp, kcpPayload)
		}
		return
	}
	// Single-peer mode (client): only accept control frames addressed
	// specifically to our control epoch. Other clients sharing the same SFU
	// room broadcast their handshake control frames with dst==0; the SFU
	// forwards those to us too. Without this filter those foreign bytes would
	// be fed into our singleton control KCP (which shares the static
	// kcpConvID) and corrupt our own handshake/liveness stream, so neither
	// client could complete its handshake (issue #95 multi-client). The
	// server always addresses a client directly (dst==clientControlEpoch),
	// so a non-targeted control frame is never legitimately ours.
	if dst != p.controlEpochValue() {
		return
	}
	// Single-peer mode: deliver to the singleton control KCP.
	p.controlKCPMu.RLock()
	crt := p.controlKCP
	p.controlKCPMu.RUnlock()
	if crt != nil {
		deliverKCPPayload(crt, kcpPayload)
	}
}

// handlePeerFrame routes incoming KCP data to a per-peer KCP runtime,
// creating one on demand. Each peer epoch gets its own independent KCP
// session so multiple clients can coexist in the same room.
func (p *streamTransport) handlePeerFrame(peerEpoch uint32, kcpPayload []byte) {
	if len(kcpPayload) == 0 {
		// Keepalive - ensure peer is registered but nothing to deliver.
		p.getOrCreatePeerKCP(peerEpoch)
		return
	}

	rt := p.getOrCreatePeerKCP(peerEpoch)
	if rt != nil {
		deliverKCPPayload(rt, kcpPayload)
	}
}

func (p *streamTransport) getOrCreatePeerKCP(epoch uint32) *kcpRuntime {
	p.peersMu.RLock()
	rt := p.peers[epoch]
	p.peersMu.RUnlock()
	if rt != nil {
		return rt
	}

	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	// Double-check after acquiring write lock.
	if rt = p.peers[epoch]; rt != nil {
		return rt
	}

	peerID := formatPeerID(epoch)
	out := make(chan []byte, outboundQueueSize)
	// Address downlink frames to the specific client epoch so other clients
	// do not ingest them (issue #95 multi-client cross-talk).
	hdr := buildEpochHeaderTo(p.bindingToken, p.localEpochValue(), epoch)
	rt, err := startKCP(out, func(data []byte) {
		if p.onPeerData != nil {
			p.onPeerData(peerID, data)
		}
	}, hdr)
	if err != nil {
		logger.Warnf("vp8channel: startKCP for peer 0x%08x failed: %v", epoch, err)
		return nil
	}
	p.peers[epoch] = rt
	p.peerOut[epoch] = out
	logger.Infof("vp8channel: peer session created epoch=0x%08x", epoch)

	// Pump outbound frames from this peer's queue into the writer.
	go p.peerWriterPump(epoch, out)

	return rt
}

// peerWriterPump drains a peer's outbound KCP queue and writes frames to the
// shared video track on the same frame ticker writerLoop uses for the
// client->server path, batching queued frames into one VP8 sample per tick.
// Draining on the ticker (rather than emitting each frame the instant it is
// queued) keeps the per-peer writes interleaved with the keyframe injection
// below and lets batchSampleFrom coalesce segments into full samples. Stops
// when the channel is closed or the transport shuts down.
func (p *streamTransport) peerWriterPump(_ uint32, out chan []byte) {
	ticker := time.NewTicker(p.frameInterval)
	defer ticker.Stop()

	// Inject a decodable VP8 keyframe on the same cadence writerLoop uses for
	// the client->server path. The server's per-peer bulk path previously
	// emitted only opaque KCP data frames, which never form a decodable VP8
	// keyframe: the SFU's decoder times out (~40s without a keyframe) and stops
	// forwarding the server's track to the subscriber. The client side was
	// kept alive by writerLoop.forceKeepalive; the server side had no
	// equivalent, so the server->client direction collapsed first while the
	// client->server direction kept flowing (issue #95).
	keyframeEvery := max(int((2*time.Second)/p.frameInterval), 1)
	ticksSinceKeyframe := 0

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			ticksSinceKeyframe++
			if ticksSinceKeyframe >= keyframeEvery {
				ticksSinceKeyframe = 0
				hdr := p.epochHeader()
				_ = p.writeSampleLocked(hdr[:])
			}
			select {
			case frame, ok := <-out:
				if !ok {
					return
				}
				sample := p.batchSampleFrom(out, frame)
				_ = p.writeSampleLocked(sample)
			default:
			}
		}
	}
}

func formatPeerID(epoch uint32) string {
	return fmt.Sprintf("%08x", epoch)
}

func parsePeerID(peerID string) (uint32, error) {
	v, err := strconv.ParseUint(peerID, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("parse peer ID %q: %w", peerID, err)
	}
	return uint32(v), nil
}

func deliverKCPPayload(rt *kcpRuntime, payload []byte) {
	if rt == nil || len(payload) == 0 {
		return
	}
	splitKCPPayload(payload, rt.deliver)
}

func splitKCPPayload(payload []byte, deliver func([]byte)) {
	if len(payload) < len(kcpBatchMagic) ||
		string(payload[:len(kcpBatchMagic)]) != string(kcpBatchMagic[:]) {
		deliver(payload)
		return
	}

	rest := payload[len(kcpBatchMagic):]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return
		}
		size := int(binary.BigEndian.Uint16(rest[:2]))
		rest = rest[2:]
		if size == 0 || len(rest) < size {
			return
		}
		deliver(rest[:size])
		rest = rest[size:]
	}
}

// ControlSend implements transport.ControlPlane.
// It sends data through the isolated control-plane KCP session.
func (p *streamTransport) ControlSend(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}
	p.controlKCPMu.RLock()
	rt := p.controlKCP
	p.controlKCPMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}
	return rt.send(data)
}

// SetControlOnData implements transport.ControlPlane.
// The callback is stored and forwarded to the control KCP read loop.
// Can be called before or after Connect; the running KCP read loop picks
// it up immediately via the closure registered in controlKCPOnce.
func (p *streamTransport) SetControlOnData(cb func([]byte)) {
	p.controlOnDataMu.Lock()
	p.onControlData = cb
	p.controlOnDataMu.Unlock()
}

// getOrCreatePeerControlKCP returns the per-peer control KCP for a data epoch,
// creating one on demand. Outbound frames go via the shared controlOutbound
// queue so writerLoop drains them with higher priority than bulk data.
func (p *streamTransport) getOrCreatePeerControlKCP(dataEpoch uint32) *peerControlKCP {
	p.ctrlPeersMu.RLock()
	pck := p.ctrlPeers[dataEpoch]
	p.ctrlPeersMu.RUnlock()
	if pck != nil {
		return pck
	}

	p.ctrlPeersMu.Lock()
	defer p.ctrlPeersMu.Unlock()
	if pck = p.ctrlPeers[dataEpoch]; pck != nil {
		return pck
	}

	peerID := formatPeerID(dataEpoch)
	// src = server's control epoch; dst = client's control epoch so the
	// client's loopback filter accepts it and other clients drop it.
	srcEpoch := p.localEpochValue() | controlEpochFlag
	dstEpoch := dataEpoch | controlEpochFlag
	hdr := buildEpochHeaderTo(p.bindingToken, srcEpoch, dstEpoch)
	cb := func(data []byte) {
		p.controlOnDataMu.RLock()
		onPeerCtrl := p.onPeerControlData
		p.controlOnDataMu.RUnlock()
		if onPeerCtrl != nil {
			onPeerCtrl(peerID, data)
		}
	}
	rt, err := startKCP(p.controlOutbound, cb, hdr)
	if err != nil {
		logger.Warnf("vp8channel: startKCP for peer control 0x%08x failed: %v", dataEpoch, err)
		return nil
	}
	pck = &peerControlKCP{kcp: rt, out: p.controlOutbound}
	p.ctrlPeers[dataEpoch] = pck
	logger.Infof("vp8channel: per-peer control KCP created peerID=%s dstControlEpoch=0x%08x", peerID, dstEpoch)
	return pck
}

// ControlSendTo sends data on the per-peer control KCP for peerID.
// Implements transport.PeerControlPlane.
func (p *streamTransport) ControlSendTo(peerID string, data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return fmt.Errorf("vp8channel: invalid peerID %q: %w", peerID, err)
	}
	pck := p.getOrCreatePeerControlKCP(epoch)
	if pck == nil {
		return ErrTransportClosed
	}
	return pck.kcp.send(data)
}

// SetControlOnPeerData registers the callback for per-peer control frames.
// Implements transport.PeerControlPlane.
func (p *streamTransport) SetControlOnPeerData(cb func(peerID string, data []byte)) {
	p.controlOnDataMu.Lock()
	p.onPeerControlData = cb
	p.controlOnDataMu.Unlock()
}

// ControlPeerCanSend reports whether the per-peer control KCP for peerID is ready.
// Implements transport.PeerControlPlane.
func (p *streamTransport) ControlPeerCanSend(peerID string) bool {
	if p.closed.Load() {
		return false
	}
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return false
	}
	p.ctrlPeersMu.RLock()
	pck := p.ctrlPeers[epoch]
	p.ctrlPeersMu.RUnlock()
	return pck != nil && p.stream.SubscriberCanSend()
}

/*
ПИДОРАС ИЗ ЯНДЕКСА СУКА ПРЕЖДЕ ЧЕМ ФИКСИТЬ ЭТО ЗАДАЙСЯ ВОПРОСОМ:
ПОЧЕМУ ТВОЙ СЕРВЕР ПРИНИМАЕТ ПАКЕТЫ С SEQUENCE NUMBER ИЗ БУДУЩЕГО
БЛЯТЬ ДА ПОТОМУ ЧТО ОН ХУЙНЯ И ТВОЯ МАТЬ СОЛСЕТ МОЙ ХУЙ СУКА Я ЕЕ УБЬЮ БЛЯТЬ
ОЕСЕНЮ СДЕЛАЮ ТЕСТО А ПОТОМ ЭТО ТЕСТО ВЫЕБУ БЛЯТЬ
*/
