// Package seichannel provides a byte transport over H264 SEI messages.
package seichannel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	enginebuiltin "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/builtin"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport/common"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"
)

const (
	defaultMaxPayloadSize        = 7 * 1024
	defaultFragmentSize          = 900
	defaultAckTimeout            = 3 * time.Second
	defaultFrameInterval         = 16 * time.Millisecond
	defaultFPS                   = 30
	defaultBatchSize             = 64
	defaultConnectTimeout        = 30 * time.Second
	maxSendAttempts              = 4
	sampleBuilderMaxLate         = 128
	protocolMagic         uint32 = 0x4f564331 // OVC1
	protocolVersion       byte   = 1
	frameTypeData         byte   = 1
	frameTypeAck          byte   = 2
	frameTypeHello        byte   = 3
)

var (
	// ErrVideoTrackUnsupported is returned when a carrier cannot expose video tracks.
	ErrVideoTrackUnsupported = errors.New("carrier does not support video tracks")
	// ErrAckTimeout is returned when the peer does not acknowledge a payload in time.
	ErrAckTimeout = errors.New("seichannel ack timeout")
	// ErrTransportClosed is returned when operations are attempted on a closed transport.
	ErrTransportClosed = errors.New("seichannel transport closed")
	// ErrFrameTooShort is returned when the received frame is too short to decode.
	ErrFrameTooShort = errors.New("frame too short")
	// ErrUnexpectedMagic is returned when the frame magic bytes do not match.
	ErrUnexpectedMagic = errors.New("unexpected frame magic")
	// ErrUnexpectedVersion is returned when the frame protocol version does not match.
	ErrUnexpectedVersion = errors.New("unexpected frame version")
	// ErrAckTooShort is returned when the ack frame is shorter than expected.
	ErrAckTooShort = errors.New("ack frame too short")
	// ErrDataTooShort is returned when the data frame is shorter than expected.
	ErrDataTooShort = errors.New("data frame too short")
	// ErrUnexpectedFrameType is returned for unknown frame type bytes.
	ErrUnexpectedFrameType = errors.New("unexpected frame type")
)

type transportFrame struct {
	typ       byte
	seq       uint32
	crc       uint32
	totalLen  uint32
	fragIdx   uint16
	fragTotal uint16
	payload   []byte
}

// videoSession is the subset of engine.Session + engine.VideoTrackCapable the
// seichannel transport relies on.
type videoSession interface {
	Connect(ctx context.Context) error
	Close() error
	SetReconnectCallback(cb func())
	SetShouldReconnect(fn func() bool)
	SetEndedCallback(cb func(string))
	WatchConnection(ctx context.Context)
	CanSend() bool
	Reconnect(reason string)
	AddTrack(track webrtc.TrackLocal) error
	SetTrackHandler(cb func(*webrtc.TrackRemote, *webrtc.RTPReceiver))
}

type streamTransport struct {
	stream        videoSession
	track         *webrtc.TrackLocalStaticSample
	onData        func([]byte)
	outbound      chan []byte
	outboundAck   chan []byte
	closeCh       chan struct{}
	writerDone    chan struct{}
	nextSeq       atomic.Uint32
	closed        atomic.Bool
	writerUp      atomic.Bool
	peerReady     atomic.Bool
	sendMu        sync.Mutex
	startWriter   sync.Once
	acks          *common.AckRegistry
	reassembler   *common.Reassembler
	fragmentSize  int
	ackTimeout    time.Duration
	frameInterval time.Duration
	batchSize     int
}

// New creates a seichannel transport backed by a carrier.
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
			MimeType:    webrtc.MimeTypeH264,
			ClockRate:   90000,
			Channels:    0,
			SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
		},
		"seichannel-"+common.RandomID(),
		"olcrtc-"+common.RandomID(),
	)
	if err != nil {
		return nil, fmt.Errorf("create local video track: %w", err)
	}

	opts = opts.withDefaults()
	tr := &streamTransport{
		stream:        stream,
		track:         track,
		onData:        cfg.OnData,
		outbound:      make(chan []byte, 256),
		outboundAck:   make(chan []byte, 64),
		closeCh:       make(chan struct{}),
		writerDone:    make(chan struct{}),
		acks:          common.NewAckRegistry(),
		reassembler:   common.NewReassembler(256),
		fragmentSize:  opts.FragmentSize,
		ackTimeout:    time.Duration(opts.AckTimeoutMS) * time.Millisecond,
		frameInterval: time.Second / time.Duration(opts.FPS),
		batchSize:     opts.BatchSize,
	}

	if err := stream.AddTrack(track); err != nil {
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	stream.SetTrackHandler(tr.handleRemoteTrack)

	return tr, nil
}

// Connect starts the transport connection.
func (p *streamTransport) Connect(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := p.stream.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	p.startWriter.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()
	})

	return nil
}

// Send transmits data through the transport.
func (p *streamTransport) Send(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	p.sendMu.Lock()
	defer p.sendMu.Unlock()

	seq := p.nextSeq.Add(1)
	crc := crc32.ChecksumIEEE(data)
	fragments := common.FragmentPayload(data, p.effectiveFragmentSize())
	waiter := p.acks.Register(seq)
	defer p.acks.Unregister(seq)

	ackTimeout := p.perAttemptAckTimeout(len(fragments))

	for attempt := range maxSendAttempts {
		// Only enqueue fragments on the first attempt. Retries just wait
		// longer - the fragments from the previous attempt are still in
		// the outbound channel being drained by writerLoop. Re-enqueuing
		// causes dead-fragment backlog that eventually clogs the channel.
		if attempt == 0 {
			for idx, fragment := range fragments {
				frame := encodeDataFrame(seq, crc, len(data), idx, len(fragments), fragment)
				if err := p.enqueueFrame(frame, false); err != nil {
					return err
				}
			}
		}

		timer := time.NewTimer(ackTimeout)
		select {
		case ackCRC := <-waiter:
			timer.Stop()
			if ackCRC == crc {
				return nil
			}
		case <-timer.C:
		case <-p.closeCh:
			timer.Stop()
			return ErrTransportClosed
		}
	}

	return ErrAckTimeout
}

// perAttemptAckTimeout computes a per-attempt timeout that accounts for the
// time writerLoop needs to drain all fragments through the FPS-paced ticker.
func (p *streamTransport) perAttemptAckTimeout(fragments int) time.Duration {
	frameInterval := p.effectiveFrameInterval()
	batchSize := p.effectiveBatchSize()
	// Drain time: how long writerLoop needs to send all fragments.
	drainTicks := (fragments + batchSize - 1) / batchSize
	drainTime := time.Duration(drainTicks) * frameInterval
	// Allow 3× drain time for scheduling jitter + peer reassembly + ack RTT.
	estimated := drainTime * 3
	floor := p.effectiveAckTimeout()
	if estimated < floor {
		return floor
	}
	const maxAckTimeout = 30 * time.Second
	if estimated > maxAckTimeout {
		return maxAckTimeout
	}
	return estimated
}

// Close terminates the transport.
func (p *streamTransport) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)
		if p.writerUp.Load() {
			<-p.writerDone
		}
		if err := p.stream.Close(); err != nil {
			return fmt.Errorf("close stream: %w", err)
		}
	}
	return nil
}

// SetReconnectCallback registers reconnect handling.
func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.stream.SetReconnectCallback(cb)
}

// Reconnect forwards to the underlying engine session.
func (p *streamTransport) Reconnect(reason string) {
	p.stream.Reconnect(reason)
}

// SetShouldReconnect configures reconnect policy.
func (p *streamTransport) SetShouldReconnect(fn func() bool) {
	p.stream.SetShouldReconnect(fn)
}

// SetEndedCallback registers end-of-session handling.
func (p *streamTransport) SetEndedCallback(cb func(string)) {
	p.stream.SetEndedCallback(cb)
}

// WatchConnection monitors connection lifecycle.
func (p *streamTransport) WatchConnection(ctx context.Context) {
	p.stream.WatchConnection(ctx)
}

// CanSend reports whether transport is ready for sending.
func (p *streamTransport) CanSend() bool {
	return !p.closed.Load() && p.peerReady.Load() && p.stream.CanSend()
}

// Features describes the current seichannel transport semantics.
func (p *streamTransport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  p.effectiveFragmentSize() * 8,
	}
}

func (p *streamTransport) effectiveFragmentSize() int {
	if p.fragmentSize <= 0 {
		return defaultFragmentSize
	}
	return p.fragmentSize
}

func (p *streamTransport) effectiveAckTimeout() time.Duration {
	if p.ackTimeout <= 0 {
		return defaultAckTimeout
	}
	return p.ackTimeout
}

func (p *streamTransport) effectiveFrameInterval() time.Duration {
	if p.frameInterval <= 0 {
		return defaultFrameInterval
	}
	return p.frameInterval
}

func (p *streamTransport) effectiveBatchSize() int {
	if p.batchSize <= 0 {
		return defaultBatchSize
	}
	return p.batchSize
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	ticker := time.NewTicker(p.effectiveFrameInterval())
	defer ticker.Stop()

	idle := buildVideoAccessUnit(encodeHelloFrame())

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			if !p.writeBatch(idle) {
				return
			}
		}
	}
}

func (p *streamTransport) writeBatch(idle []byte) bool {
	frameInterval := p.effectiveFrameInterval()
	batchSize := p.effectiveBatchSize()
	for i := range batchSize {
		payload, ok := p.nextOutboundFrame()
		if !ok {
			return false
		}
		if payload == nil {
			if i > 0 {
				return true
			}
			_ = p.track.WriteSample(media.Sample{Data: idle, Duration: frameInterval})
			return true
		}
		_ = p.track.WriteSample(media.Sample{Data: buildVideoAccessUnit(payload), Duration: frameInterval})
	}
	return true
}

func (p *streamTransport) nextOutboundFrame() ([]byte, bool) {
	select {
	case <-p.closeCh:
		return nil, false
	case payload := <-p.outboundAck:
		return payload, true
	default:
	}

	select {
	case <-p.closeCh:
		return nil, false
	case payload := <-p.outboundAck:
		return payload, true
	case payload := <-p.outbound:
		return payload, true
	default:
		return nil, true
	}
}

func (p *streamTransport) enqueueFrame(frame []byte, priority bool) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	ch := p.outbound
	if priority {
		ch = p.outboundAck
	}

	select {
	case <-p.closeCh:
		return ErrTransportClosed
	case ch <- frame:
		return nil
	}
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	go func() {
		sb := samplebuilder.New(sampleBuilderMaxLate, &codecs.H264Packet{}, track.Codec().ClockRate)

		popSamples := func() {
			for sample := sb.Pop(); sample != nil; sample = sb.Pop() {
				p.handleSample(sample.Data)
			}
		}

		for {
			packet, _, err := track.ReadRTP()
			if err != nil {
				sb.Flush()
				popSamples()
				return
			}

			sb.Push(packet)
			popSamples()
		}
	}()
}

func (p *streamTransport) handleSample(sample []byte) {
	payloads, err := extractVideoPayloads(sample)
	if err != nil {
		return
	}

	for _, payload := range payloads {
		frame, err := decodeTransportFrame(payload)
		if err != nil {
			continue
		}

		switch frame.typ {
		case frameTypeHello:
			p.peerReady.Store(true)
		case frameTypeAck:
			p.peerReady.Store(true)
			p.resolveAck(frame.seq, frame.crc)
		case frameTypeData:
			p.peerReady.Store(true)
			p.handleInboundFrame(frame)
		}
	}
}

func (p *streamTransport) handleInboundFrame(frame transportFrame) {
	result, data := p.reassembler.Push(common.Fragment{
		Seq:       frame.seq,
		CRC:       frame.crc,
		TotalLen:  frame.totalLen,
		FragIdx:   frame.fragIdx,
		FragTotal: frame.fragTotal,
		Payload:   frame.payload,
	})
	switch result {
	case common.ResultDuplicate:
		p.sendAck(frame.seq, frame.crc)
	case common.ResultDelivered:
		if p.onData != nil {
			p.onData(data)
		}
		p.sendAck(frame.seq, frame.crc)
	case common.ResultPartial, common.ResultIgnore:
		// fragment stored or discarded; no peer response needed yet.
	}
}

func (p *streamTransport) sendAck(seq, crc uint32) {
	_ = p.enqueueFrame(encodeAckFrame(seq, crc), true)
}

func (p *streamTransport) resolveAck(seq, crc uint32) {
	p.acks.Resolve(seq, crc)
}

func encodeDataFrame(seq, crc uint32, totalLen, fragIdx, fragTotal int, payload []byte) []byte {
	out := make([]byte, 22+len(payload))
	binary.BigEndian.PutUint32(out[0:4], protocolMagic)
	out[4] = protocolVersion
	out[5] = frameTypeData
	binary.BigEndian.PutUint32(out[6:10], seq)
	binary.BigEndian.PutUint32(out[10:14], crc)
	binary.BigEndian.PutUint32(out[14:18], uint32(totalLen))  //nolint:gosec,lll // G115: bounded conversion verified by surrounding logic
	binary.BigEndian.PutUint16(out[18:20], uint16(fragIdx))   //nolint:gosec,lll // G115: bounded conversion verified by surrounding logic
	binary.BigEndian.PutUint16(out[20:22], uint16(fragTotal)) //nolint:gosec,lll // G115: bounded conversion verified by surrounding logic
	copy(out[22:], payload)
	return out
}

func encodeAckFrame(seq, crc uint32) []byte {
	out := make([]byte, 14)
	binary.BigEndian.PutUint32(out[0:4], protocolMagic)
	out[4] = protocolVersion
	out[5] = frameTypeAck
	binary.BigEndian.PutUint32(out[6:10], seq)
	binary.BigEndian.PutUint32(out[10:14], crc)
	return out
}

func encodeHelloFrame() []byte {
	out := make([]byte, 6)
	binary.BigEndian.PutUint32(out[0:4], protocolMagic)
	out[4] = protocolVersion
	out[5] = frameTypeHello
	return out
}

func decodeTransportFrame(data []byte) (transportFrame, error) {
	if len(data) < 6 {
		return transportFrame{}, ErrFrameTooShort
	}
	if binary.BigEndian.Uint32(data[0:4]) != protocolMagic {
		return transportFrame{}, ErrUnexpectedMagic
	}
	if data[4] != protocolVersion {
		return transportFrame{}, ErrUnexpectedVersion
	}

	frame := transportFrame{typ: data[5]}
	switch frame.typ {
	case frameTypeHello:
		return frame, nil
	case frameTypeAck:
		if len(data) < 14 {
			return transportFrame{}, ErrAckTooShort
		}
		frame.seq = binary.BigEndian.Uint32(data[6:10])
		frame.crc = binary.BigEndian.Uint32(data[10:14])
		return frame, nil
	case frameTypeData:
		if len(data) < 22 {
			return transportFrame{}, ErrDataTooShort
		}
		frame.seq = binary.BigEndian.Uint32(data[6:10])
		frame.crc = binary.BigEndian.Uint32(data[10:14])
		frame.totalLen = binary.BigEndian.Uint32(data[14:18])
		frame.fragIdx = binary.BigEndian.Uint16(data[18:20])
		frame.fragTotal = binary.BigEndian.Uint16(data[20:22])
		frame.payload = append([]byte(nil), data[22:]...)
		return frame, nil
	default:
		return transportFrame{}, ErrUnexpectedFrameType
	}
}
