// Package videochannel provides a byte transport over a visual video stream.
package videochannel

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	enginebuiltin "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/builtin"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport/common"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"
)

const (
	defaultMaxPayloadSize = 16 * 1024
	defaultFragmentSize   = 256
	defaultAckTimeout     = 1 * time.Second
	defaultFrameInterval  = 40 * time.Millisecond
	defaultConnectTimeout = 30 * time.Second
	maxSendAttempts       = 20
	sampleBuilderMaxLate  = 128
)

var (
	// ErrVideoTrackUnsupported is returned when a carrier cannot expose video tracks.
	ErrVideoTrackUnsupported = errors.New("carrier does not support video tracks")
	// ErrAckTimeout is returned when the peer does not acknowledge a payload in time.
	ErrAckTimeout = errors.New("videochannel ack timeout")
	// ErrTransportClosed is returned when operations are attempted on a closed transport.
	ErrTransportClosed = errors.New("videochannel transport closed")
)

// videoSession is the subset of engine.Session + engine.VideoTrackCapable
// the videochannel transport relies on.
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
	stream          videoSession
	track           *webrtc.TrackLocalStaticSample
	codec           codecSpec
	encoder         *goEncoder
	encoderMu       sync.Mutex
	decoderMu       sync.Mutex
	decoders        map[*goDecoder]struct{}
	onData          func([]byte)
	outbound        chan []byte
	outboundAck     chan []byte
	closeCh         chan struct{}
	writerDone      chan struct{}
	nextSeq         atomic.Uint32
	closed          atomic.Bool
	writerUp        atomic.Bool
	sendMu          sync.Mutex
	startWriter     sync.Once
	fragAcks        *fragAckTracker
	reassembler     *common.Reassembler
	videoW          int
	videoH          int
	videoFPS        int
	videoBitrate    string
	videoHW         string
	videoQRSize     int
	videoQRRecovery string
	videoCodec      string
	videoTileModule int
	videoTileRS     int
	localRole       byte
	remoteRole      byte
	bindingToken    uint32
	runCtx          context.Context //nolint:containedctx,lll // long-lived context drives idle-frame loops bound to this transport's lifetime
}

// New creates a visual videochannel transport backed by a carrier engine.
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

	codec := codecSpecForCarrier(cfg.Carrier)
	// Stream/track IDs must be unique per peer: Jitsi/Jicofo keys participant
	// sources by msid (stream-id+track-id) and rejects a session-accept whose
	// msid collides with one already in the conference.
	streamID := "videochannel-" + common.RandomID()
	trackID := "olcrtc-" + common.RandomID()
	track, err := webrtc.NewTrackLocalStaticSample(codec.capability, streamID, trackID)
	if err != nil {
		return nil, fmt.Errorf("create local video track: %w", err)
	}

	qrSize := opts.QRSize
	if qrSize <= 0 {
		qrSize = defaultFragmentSize
	}

	tileModule := opts.TileModule
	if tileModule <= 0 {
		tileModule = 4
	}

	tileRS := opts.TileRS
	if tileRS < 0 {
		tileRS = 20
	}

	tr := &streamTransport{
		stream:          stream,
		track:           track,
		codec:           codec,
		onData:          cfg.OnData,
		outbound:        make(chan []byte, 256),
		outboundAck:     make(chan []byte, 64),
		closeCh:         make(chan struct{}),
		writerDone:      make(chan struct{}),
		decoders:        make(map[*goDecoder]struct{}),
		fragAcks:        newFragAckTracker(),
		reassembler:     common.NewReassembler(256),
		videoW:          opts.Width,
		videoH:          opts.Height,
		videoFPS:        opts.FPS,
		videoBitrate:    opts.Bitrate,
		videoHW:         opts.HW,
		videoQRSize:     qrSize,
		videoQRRecovery: opts.QRRecovery,
		videoCodec:      opts.Codec,
		videoTileModule: tileModule,
		videoTileRS:     tileRS,
		localRole:       localFrameRole(cfg.DeviceID),
		remoteRole:      remoteFrameRole(cfg.DeviceID),
		bindingToken:    bindingToken(cfg.ChannelID),
		runCtx:          ctx,
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

	encoder := newGoEncoder(p.videoW, p.videoH, p.videoFPS)

	if err := p.stream.Connect(connectCtx); err != nil {
		_ = encoder.Close()
		return fmt.Errorf("connect stream: %w", err)
	}

	p.encoderMu.Lock()
	if p.closed.Load() {
		p.encoderMu.Unlock()
		_ = encoder.Close()
		return ErrTransportClosed
	}
	if p.encoder != nil {
		_ = p.encoder.Close()
	}
	p.encoder = encoder
	p.encoderMu.Unlock()

	p.startWriter.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()
	})

	return nil
}

// Send transmits data through the transport with per-fragment retransmits.
//
// QR/tile-encoded fragments ride lossy VP8 video frames where any single
// fragment can be corrupted past ECC recovery. With whole-message ack
// semantics a single dropped fragment forced a full retransmit; under
// load that piled fragments into the outbound channel and eventually
// killed the encoder. Here each fragment is acked independently and only
// the unacked ones are resent.
func (p *streamTransport) Send(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	p.sendMu.Lock()
	defer p.sendMu.Unlock()

	seq := p.nextSeq.Add(1)
	crc := crc32.ChecksumIEEE(data)
	fragments := common.FragmentPayload(data, p.videoQRSize)
	waiter := p.fragAcks.Register(seq, crc, len(fragments))
	defer p.fragAcks.Unregister(seq)

	// Per-attempt wait covers one round trip through the FPS-paced writer
	// and the peer's reassembly + ack path. Scale with fragment count so a
	// large payload gets enough time to drain on the first attempt before
	// we retransmit anything.
	ackTimeout := perAttemptAckTimeout(len(fragments), p.videoFPS)

	// Initial send: every fragment goes out once.
	pending := make([]int, len(fragments))
	for i := range pending {
		pending[i] = i
	}

	for range maxSendAttempts {
		for _, idx := range pending {
			frame := encodeDataFrameForBinding(
				p.localRole, p.bindingToken, seq, crc,
				len(data), idx, len(fragments), fragments[idx])
			if err := p.enqueueFrame(frame, false); err != nil {
				return err
			}
		}

		if ok, err := p.awaitFragments(waiter, ackTimeout); err != nil {
			return err
		} else if ok {
			return nil
		}
		pending = waiter.Pending()
		if len(pending) == 0 {
			return nil
		}
	}

	return ErrAckTimeout
}

// awaitFragments blocks until the waiter is fully acked, the per-attempt
// timeout elapses, or the transport closes. Returns (done, err).
func (p *streamTransport) awaitFragments(waiter *fragWaiter, timeout time.Duration) (bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if waiter.Done() {
			return true, nil
		}
		select {
		case <-waiter.Notify():
			// Re-check Done() at the top of the loop.
		case <-timer.C:
			return waiter.Done(), nil
		case <-p.closeCh:
			return false, ErrTransportClosed
		}
	}
}

// perAttemptAckTimeout returns how long to wait for acks of a multi-fragment
// payload before retransmitting unacked fragments. Floor at defaultAckTimeout
// for tiny payloads; otherwise scale linearly with fragment count to cover
// one round trip through the FPS-paced writerLoop plus reassembly on the peer
// side, with a 3× margin.
func perAttemptAckTimeout(fragments, fps int) time.Duration {
	if fps <= 0 {
		fps = 25
	}
	frameInterval := time.Second / time.Duration(fps)
	estimated := time.Duration(fragments) * frameInterval * 3
	if estimated < defaultAckTimeout {
		return defaultAckTimeout
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

		p.encoderMu.Lock()
		if p.encoder != nil {
			_ = p.encoder.Close()
		}
		p.encoderMu.Unlock()

		p.decoderMu.Lock()
		for decoder := range p.decoders {
			_ = decoder.Close()
		}
		p.decoders = nil
		p.decoderMu.Unlock()

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
	return !p.closed.Load() && p.stream.CanSend()
}

// Features describes the current videochannel transport semantics.
func (p *streamTransport) Features() transport.Features {
	maxPayload := defaultMaxPayloadSize
	if p.videoQRSize*64 > maxPayload {
		maxPayload = p.videoQRSize * 64
	}
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  maxPayload,
	}
}

func (p *streamTransport) writeIdleFrame(enc *goEncoder, frameDuration time.Duration) {
	rawFrame, err := p.renderFrame(nil)
	if err != nil {
		logger.Debugf("videochannel render idle error: %v", err)
		return
	}
	sample, err := enc.EncodeFrame(rawFrame)
	if err != nil {
		logger.Warnf("videochannel encoder idle error: %v", err)
		return
	}

	_ = p.track.WriteSample(media.Sample{Data: sample, Duration: frameDuration})
}

func (p *streamTransport) writePayloadFrame(enc *goEncoder, payload []byte, frameDuration time.Duration) {
	rawFrame, err := p.renderFrame(payload)
	if err != nil {
		logger.Debugf("videochannel render error: %v", err)
		return
	}

	sample, err := enc.EncodeFrame(rawFrame)
	if err != nil {
		logger.Warnf("videochannel encoder error: %v", err)
		return
	}

	_ = p.track.WriteSample(media.Sample{Data: sample, Duration: frameDuration})
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)
	defer func() {
		p.encoderMu.Lock()
		defer p.encoderMu.Unlock()
		if p.encoder != nil {
			_ = p.encoder.Close()
		}
	}()

	ticker := time.NewTicker(time.Second / time.Duration(p.videoFPS))
	defer ticker.Stop()

	frameDuration := time.Second / time.Duration(p.videoFPS)

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			payload, ok := p.nextOutboundFrame()
			if !ok {
				return
			}

			p.encoderMu.Lock()
			enc := p.encoder
			p.encoderMu.Unlock()

			if enc == nil {
				continue
			}

			if payload == nil {
				p.writeIdleFrame(enc, frameDuration)
			} else {
				p.writePayloadFrame(enc, payload, frameDuration)
			}
		}
	}
}

func (p *streamTransport) renderFrame(payload []byte) ([]byte, error) {
	return renderVisualFrame(
		payload,
		p.videoW, p.videoH,
		p.videoCodec, p.videoQRRecovery,
		p.videoTileModule, p.videoTileRS,
	)
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

func (p *streamTransport) popDecoderFrames(decoder *goDecoder) {
	defer func() {
		p.decoderMu.Lock()
		if p.decoders != nil {
			delete(p.decoders, decoder)
		}
		p.decoderMu.Unlock()
		_ = decoder.Close()
	}()

	for {
		select {
		case <-p.closeCh:
			return
		default:
		}

		frame, err := decoder.PopFrame()
		if err != nil {
			if !errors.Is(err, ErrTransportClosed) && !p.closed.Load() {
				logger.Warnf("videochannel decoder pop error: %v", err)
			}
			return
		}
		p.handleFrame(frame)
	}
}

func (p *streamTransport) readDecoderInput(track *webrtc.TrackRemote, decoder *goDecoder, codec codecSpec) {
	sb := samplebuilder.New(sampleBuilderMaxLate, codec.depacketizer(), track.Codec().ClockRate)
	for {
		select {
		case <-p.closeCh:
			return
		default:
		}

		packet, _, err := track.ReadRTP()
		if err != nil {
			sb.Flush()
			return
		}

		sb.Push(packet)
		for sample := sb.Pop(); sample != nil; sample = sb.Pop() {
			if err := decoder.PushSample(sample.Data); err != nil {
				if !p.closed.Load() {
					logger.Warnf("videochannel decoder push error: %v", err)
				}
				return
			}
		}
	}
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	codec, ok := codecSpecForMime(track.Codec().MimeType)
	if !ok {
		logger.Warnf("videochannel unsupported remote codec: %s", track.Codec().MimeType)
		return
	}

	decoder := newGoDecoder(p.videoW, p.videoH)

	p.decoderMu.Lock()
	if p.closed.Load() || p.decoders == nil {
		p.decoderMu.Unlock()
		_ = decoder.Close()
		return
	}
	p.decoders[decoder] = struct{}{}
	p.decoderMu.Unlock()

	go p.popDecoderFrames(decoder)
	go p.readDecoderInput(track, decoder, codec)
}

func (p *streamTransport) handleFrame(frame []byte) {
	var payload []byte
	var err error
	payload, err = extractVisualPayload(frame, p.videoW, p.videoH, p.videoCodec, p.videoTileModule, p.videoTileRS)
	if err != nil || len(payload) == 0 {
		if err != nil {
			logger.Debugf("videochannel extract visual payload error: %v", err)
		}
		return
	}

	decoded, err := decodeTransportFrame(payload)
	if err != nil {
		logger.Debugf("videochannel decode transport frame error: %v", err)
		return
	}
	if !p.acceptFrame(decoded) {
		return
	}

	switch decoded.typ {
	case frameTypeAck:
		p.resolveAck(decoded.seq, decoded.crc, decoded.fragIdx)
	case frameTypeData:
		p.handleInboundFrame(decoded)
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
	case common.ResultDelivered:
		if p.onData != nil {
			p.onData(data)
		}
		// All fragments of this seq are in; ack this fragment. The sender
		// learns full delivery once it has accumulated acks for every
		// fragment it sent.
		p.sendAck(frame.seq, frame.crc, frame.fragIdx)
	case common.ResultPartial, common.ResultDuplicate:
		// Every fragment we successfully decoded gets acked, including
		// duplicates - under retransmits the sender may have lost the
		// earlier ack and is waiting on this one.
		p.sendAck(frame.seq, frame.crc, frame.fragIdx)
	case common.ResultIgnore:
		// Malformed or out-of-range; no ack.
	}
}

func (p *streamTransport) sendAck(seq, crc uint32, fragIdx uint16) {
	_ = p.enqueueFrame(encodeAckFrameForBinding(p.localRole, p.bindingToken, seq, crc, fragIdx), true)
}

func (p *streamTransport) resolveAck(seq, crc uint32, fragIdx uint16) {
	p.fragAcks.Mark(seq, crc, int(fragIdx))
}

func localFrameRole(deviceID string) byte {
	if deviceID == "" {
		return frameRoleServer
	}
	return frameRoleClient
}

func remoteFrameRole(deviceID string) byte {
	if deviceID == "" {
		return frameRoleClient
	}
	return frameRoleServer
}

func bindingToken(channelID string) uint32 {
	token := crc32.ChecksumIEEE([]byte(channelID))
	if token == 0 && channelID != "" {
		token = 1
	}
	return token
}

func (p *streamTransport) acceptFrame(frame transportFrame) bool {
	roleOK := frame.role == frameRoleAny || frame.role == p.remoteRole
	bindingOK := frame.binding == 0 || frame.binding == p.bindingToken
	return roleOK && bindingOK
}
