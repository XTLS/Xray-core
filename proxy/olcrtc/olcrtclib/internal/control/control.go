// Package control implements the post-handshake control stream protocol.
//
// The control stream is the first smux stream after the olcrtc handshake. It
// stays inside the encrypted muxconn path, so ping/pong proves that the actual
// tunnel path still round-trips, not merely that the provider connection is up.
//
// Wire format matches the handshake framing: a 4-byte big-endian length
// followed by a JSON message.
//
//nolint:tagliatelle // JSON keys are the stable wire protocol schema.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/framing"
)

const (
	// ProtoVersion identifies the control stream wire format.
	ProtoVersion = 1
	// MaxMessageSize caps one control frame.
	MaxMessageSize = 16 * 1024
	// DefaultInterval is the default interval between ping probes.
	DefaultInterval = 10 * time.Second
	// DefaultTimeout is the default time to wait for a pong. Generous because
	// the ping shares the bulk smux/KCP stream: under a heavy transfer the
	// ping byte can be head-of-line blocked behind queued data for several
	// seconds, which is liveness-OK, not a dead link.
	//
	// Conservative default: a conventional carrier (jitsi/datachannel) that
	// goes silent this long is genuinely dead and should reconnect promptly.
	// Video-paced transports with isolated control planes (vp8channel) need a
	// longer window because KCP batching + frame pacing can delay control
	// packets under load (issue #95); that relaxed window is applied per
	// transport via runtime.LivenessTimeout, not by widening this default.
	DefaultTimeout = 15 * time.Second
	// DefaultFailures is the default number of consecutive missed pongs before
	// the stream is marked unhealthy.
	DefaultFailures = 4
)

// MsgType labels a control message.
type MsgType string

const (
	// TypePing is sent periodically to prove control-stream liveness.
	TypePing MsgType = "CONTROL_PING"
	// TypePong replies to a ping with the same sequence and timestamp.
	TypePong MsgType = "CONTROL_PONG"
	// TypeClose tells the peer this control session is intentionally closing.
	TypeClose MsgType = "CONTROL_CLOSE"
)

var (
	// ErrUnhealthy is returned when the stream misses too many pong replies.
	ErrUnhealthy = errors.New("control stream unhealthy")
	// ErrClosedByPeer is returned when the peer gracefully closes the control session.
	ErrClosedByPeer = errors.New("control stream closed by peer")
	// ErrProtocolVersion is returned when the peer announces an incompatible version.
	ErrProtocolVersion = errors.New("incompatible control protocol version")
	// ErrUnexpectedMessage is returned for unknown or malformed control message types.
	ErrUnexpectedMessage = errors.New("unexpected control message")
	// ErrFrameTooLarge is returned when a frame exceeds [MaxMessageSize].
	ErrFrameTooLarge = framing.ErrFrameTooLarge
)

// Message is one control-stream frame.
type Message struct {
	Version      int     `json:"version"`
	Type         MsgType `json:"type"`
	Seq          uint64  `json:"seq,omitempty"`
	SentUnixNano int64   `json:"sent_unix_nano,omitempty"`
}

// Health is reported when a ping round trip completes.
type Health struct {
	Seq      uint64
	RTT      time.Duration
	LastSeen time.Time
}

// Status is a point-in-time view of control-stream health maintained by
// callers that embed the control loop.
type Status struct {
	SessionID       string
	LastPong        time.Time
	LastRTT         time.Duration
	MissedPongs     int
	Reconnects      uint64
	UnhealthyEvents uint64
	LastUnhealthy   time.Time
}

// Config controls the liveness loop.
type Config struct {
	Interval time.Duration
	Timeout  time.Duration
	Failures int

	// OnPong is called after a matching pong is received.
	OnPong func(Health)
	// OnMissedPong is called when one or more outstanding pongs time out.
	OnMissedPong func(missed int)
	// OnUnhealthy is called before Run returns [ErrUnhealthy].
	OnUnhealthy func(missed int)
}

func (cfg Config) withDefaults() Config {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Failures <= 0 {
		cfg.Failures = DefaultFailures
	}
	return cfg
}

// Run drives bidirectional ping/pong liveness until ctx is canceled, rw closes,
// or the configured failure threshold is reached.
func Run(ctx context.Context, rw io.ReadWriteCloser, cfg Config) error {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	state := &state{
		rw:      rw,
		cfg:     cfg,
		pending: make(map[uint64]time.Time),
		now:     time.Now,
		out:     make(chan Message, 16),
	}

	errCh := make(chan error, 3)
	go func() {
		<-ctx.Done()
		_ = rw.Close()
	}()
	go func() { errCh <- state.readLoop(ctx) }()
	go func() { errCh <- state.probeLoop(ctx) }()
	go func() { errCh <- state.writeLoop(ctx) }()

	err := <-errCh
	cancel()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

type state struct {
	rw  io.ReadWriteCloser
	cfg Config
	now func() time.Time

	out chan Message

	mu       sync.Mutex
	pending  map[uint64]time.Time
	nextSeq  uint64
	failures int
}

func (s *state) readLoop(ctx context.Context) error {
	for {
		raw, err := readFrame(s.rw)
		if err != nil {
			return readLoopErr(ctx, err)
		}
		msg, err := parseMessage(raw)
		if err != nil {
			return err
		}
		if err := s.handleReadMessage(ctx, msg); err != nil {
			return err
		}
	}
}

func readLoopErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("read loop canceled: %w", ctx.Err())
	}
	return err
}

func (s *state) handleReadMessage(ctx context.Context, msg Message) error {
	switch msg.Type {
	case TypePing:
		return s.enqueuePong(ctx, msg)
	case TypePong:
		s.handlePong(msg)
		return nil
	case TypeClose:
		return ErrClosedByPeer
	default:
		return fmt.Errorf("%w: got %q", ErrUnexpectedMessage, msg.Type)
	}
}

func (s *state) enqueuePong(ctx context.Context, ping Message) error {
	err := s.enqueue(ctx, Message{
		Version:      ProtoVersion,
		Type:         TypePong,
		Seq:          ping.Seq,
		SentUnixNano: ping.SentUnixNano,
	})
	if err != nil {
		return readLoopErr(ctx, err)
	}
	return nil
}

func (s *state) probeLoop(ctx context.Context) error {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("probe loop canceled: %w", ctx.Err())
		case <-ticker.C:
			if err := s.sendProbe(ctx); err != nil {
				return err
			}
		}
	}
}

func (s *state) sendProbe(ctx context.Context) error {
	now := s.now()

	s.mu.Lock()
	missedNow := 0
	for seq, sent := range s.pending {
		if now.Sub(sent) < s.cfg.Timeout {
			continue
		}
		delete(s.pending, seq)
		s.failures++
		missedNow++
	}
	missed := s.failures
	if s.failures >= s.cfg.Failures {
		s.mu.Unlock()
		if missedNow > 0 && s.cfg.OnMissedPong != nil {
			s.cfg.OnMissedPong(missed)
		}
		if s.cfg.OnUnhealthy != nil {
			s.cfg.OnUnhealthy(missed)
		}
		return fmt.Errorf("%w: missed %d pong(s)", ErrUnhealthy, missed)
	}

	s.nextSeq++
	seq := s.nextSeq
	s.pending[seq] = now
	s.mu.Unlock()
	if missedNow > 0 && s.cfg.OnMissedPong != nil {
		s.cfg.OnMissedPong(missed)
	}

	return s.enqueue(ctx, Message{
		Version:      ProtoVersion,
		Type:         TypePing,
		Seq:          seq,
		SentUnixNano: now.UnixNano(),
	})
}

func (s *state) handlePong(msg Message) {
	now := s.now()

	s.mu.Lock()
	sent, ok := s.pending[msg.Seq]
	if ok {
		delete(s.pending, msg.Seq)
		s.failures = 0
	}
	s.mu.Unlock()

	if !ok || s.cfg.OnPong == nil {
		return
	}
	s.cfg.OnPong(Health{
		Seq:      msg.Seq,
		RTT:      now.Sub(sent),
		LastSeen: now,
	})
}

func (s *state) enqueue(ctx context.Context, msg Message) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("enqueue canceled: %w", ctx.Err())
	case s.out <- msg:
		return nil
	}
}

func (s *state) writeLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("write loop canceled: %w", ctx.Err())
		case msg := <-s.out:
			if err := writeFrame(s.rw, msg); err != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("write loop canceled: %w", ctx.Err())
				}
				return err
			}
		}
	}
}

func parseMessage(raw []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, fmt.Errorf("parse control message: %w", err)
	}
	if msg.Version != ProtoVersion {
		return Message{}, fmt.Errorf("%w: peer v%d, local v%d",
			ErrProtocolVersion, msg.Version, ProtoVersion)
	}
	if msg.Type != TypePing && msg.Type != TypePong && msg.Type != TypeClose {
		return Message{}, fmt.Errorf("%w: got %q", ErrUnexpectedMessage, msg.Type)
	}
	return msg, nil
}

// SendClose sends a best-effort graceful close notification on the control stream.
func SendClose(w io.Writer) error {
	return writeFrame(w, Message{Version: ProtoVersion, Type: TypeClose})
}

func writeFrame(w io.Writer, msg Message) error {
	if err := framing.WriteJSON(w, msg, MaxMessageSize); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	body, err := framing.ReadBytes(r, MaxMessageSize)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	return body, nil
}
