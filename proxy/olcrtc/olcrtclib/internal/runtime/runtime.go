// Package runtime holds infrastructure shared by the olcrtc server and
// client: smux tuning, cipher setup, and control-stream health bookkeeping.
// The lifecycle differences between server and client (accept loop / SOCKS5
// dial vs. SOCKS5 listener / tunnel) live in their respective packages.
package runtime

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/control"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/crypto"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/xtaci/smux"
)

const (
	// SmuxFrameOverhead is the fixed smux frame header size. MaxFrameSize
	// caps only the smux payload, while muxconn encrypts and sends the whole
	// smux frame as one transport message.
	SmuxFrameOverhead = 8
	// SmuxWireOverhead is the non-payload overhead added around each smux
	// frame before it reaches the transport payload limit.
	SmuxWireOverhead = crypto.WireOverhead + SmuxFrameOverhead
	// MinSmuxWirePayload is the smallest useful encrypted transport payload
	// cap that can still carry a non-empty smux frame.
	MinSmuxWirePayload = SmuxWireOverhead + 1

	smuxMaxFrameSize     = 32 * 1024
	smuxMaxReceiveBuffer = 8 * 1024 * 1024
	smuxMaxStreamBuffer  = 512 * 1024
)

// ErrKeyRequired is returned when no encryption key is provided.
var ErrKeyRequired = errors.New("key required (use -key <hex>)")

// ErrKeySize is returned when the encryption key is not 32 bytes.
var ErrKeySize = errors.New("key must be 32 bytes")

// SetupCipher decodes a 64-char hex key and instantiates the AEAD cipher.
func SetupCipher(keyHex string) (*crypto.Cipher, error) {
	if keyHex == "" {
		return nil, ErrKeyRequired
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w, got %d", ErrKeySize, len(key))
	}
	cipher, err := crypto.NewCipher(string(key))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return cipher, nil
}

// SmuxConfig returns the tuned smux config used on both ends. Both peers
// must agree on Version and MaxFrameSize. maxWirePayload, when > 0,
// constrains the smux payload size so the encrypted whole smux frame fits
// under the transport's per-message payload cap.
func SmuxConfig(maxWirePayload int) *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveDisabled = false
	cfg.MaxFrameSize = smuxMaxFrameSize
	if maxWirePayload >= MinSmuxWirePayload {
		maxFrameSize := maxWirePayload - SmuxWireOverhead
		if maxFrameSize < cfg.MaxFrameSize {
			cfg.MaxFrameSize = maxFrameSize
		}
	}
	cfg.MaxReceiveBuffer = smuxMaxReceiveBuffer
	cfg.MaxStreamBuffer = smuxMaxStreamBuffer
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}

// SmuxConfigLong is SmuxConfig with a relaxed keep-alive timeout for
// transports whose carrier can legitimately go silent for tens of seconds
// (vp8channel/goolom publisher-PC reconnect + SFU renegotiation). A tight
// timeout would tear down the smux session while the carrier is rebuilding
// itself, forcing an unnecessary second reconnect. Only transports that
// implement transport.ControlPlane use this; conventional carriers
// (jitsi/datachannel) keep the conservative 30s timeout so a genuinely dead
// link is detected and reconnected promptly.
func SmuxConfigLong(maxWirePayload int) *smux.Config {
	cfg := SmuxConfig(maxWirePayload)
	cfg.KeepAliveTimeout = 120 * time.Second
	return cfg
}

// IsControlPlane reports whether the transport routes control-plane traffic
// on an isolated channel (transport.ControlPlane). The relaxed liveness/
// keep-alive windows are scoped to these transports only.
func IsControlPlane(tr transport.Transport) bool {
	_, ok := tr.(transport.ControlPlane)
	return ok
}

// SmuxConfigFor returns the data-plane smux config appropriate for the
// transport: relaxed keep-alive for ControlPlane carriers, conservative
// otherwise.
func SmuxConfigFor(tr transport.Transport) *smux.Config {
	maxWirePayload := MaxPayload(tr)
	if IsControlPlane(tr) {
		return SmuxConfigLong(maxWirePayload)
	}
	return SmuxConfig(maxWirePayload)
}

// LivenessTimeout returns the control-stream pong timeout for a transport:
// a relaxed window for ControlPlane transports (KCP batching + frame pacing
// can delay control packets under load), and the conservative default for
// conventional carriers so dead links are detected quickly.
func LivenessTimeout(tr transport.Transport) time.Duration {
	if IsControlPlane(tr) {
		return 45 * time.Second
	}
	return control.DefaultTimeout
}

// ConnectAckTimeout returns the tunnel CONNECT ack read deadline for a
// transport. ControlPlane transports (SFU renegotiation) may take ~30s to
// start forwarding data frames, so they get a generous window; conventional
// carriers use the conservative default.
func ConnectAckTimeout(tr transport.Transport) time.Duration {
	if IsControlPlane(tr) {
		return 90 * time.Second
	}
	return 15 * time.Second
}

// ControlSmuxConfig returns a lean smux config for the isolated control-plane
// session. The control session carries only tiny ping/pong frames so we use
// small stream buffers and disable smux keepalives (the olcrtc control.Run
// ping loop handles liveness itself).
func ControlSmuxConfig(maxWirePayload int) *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxFrameSize = smuxMaxFrameSize
	if maxWirePayload >= MinSmuxWirePayload {
		maxFrameSize := maxWirePayload - SmuxWireOverhead
		if maxFrameSize < cfg.MaxFrameSize {
			cfg.MaxFrameSize = maxFrameSize
		}
	}
	// Tiny buffers: control frames are at most a few hundred bytes.
	cfg.MaxReceiveBuffer = 256 * 1024
	cfg.MaxStreamBuffer = 32 * 1024
	// Disable smux keepalive - control.Run runs its own ping/pong loop.
	cfg.KeepAliveDisabled = true
	return cfg
}

// MaxPayload reports the transport's per-message payload limit. Returns 0
// when the transport sets no explicit limit; the caller treats 0 as "use
// SmuxConfig's default frame size".
func MaxPayload(tr transport.Transport) int {
	return tr.Features().MaxPayloadSize
}

// HealthTracker holds the live snapshot of one side's control-stream
// health: last pong time, last RTT, miss counts, reconnect counts.
// Server and client both embed a HealthTracker to avoid open-coding the
// same record* methods on both sides.
type HealthTracker struct {
	mu     sync.RWMutex
	status control.Status
	notify func(control.Status)
}

// NewHealthTracker creates a HealthTracker that publishes the latest
// snapshot through notify whenever it changes. notify may be nil.
func NewHealthTracker(notify func(control.Status)) *HealthTracker {
	if notify == nil {
		notify = func(control.Status) {}
	}
	return &HealthTracker{notify: notify}
}

// Status returns the latest health snapshot. A nil tracker reports a zero
// value, which lets tests instantiate stub Server/Client structs without
// wiring up a real tracker.
func (h *HealthTracker) Status() control.Status {
	if h == nil {
		return control.Status{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.status
}

// RecordSession resets miss counters and stamps the session id.
func (h *HealthTracker) RecordSession(id string) {
	h.update(func(s *control.Status) {
		s.SessionID = id
		s.MissedPongs = 0
	})
}

// RecordPong updates LastPong/LastRTT and clears MissedPongs.
func (h *HealthTracker) RecordPong(p control.Health) {
	h.update(func(s *control.Status) {
		s.LastPong = p.LastSeen
		s.LastRTT = p.RTT
		s.MissedPongs = 0
	})
}

// RecordMissed bumps the missed-pong count.
func (h *HealthTracker) RecordMissed(missed int) {
	h.update(func(s *control.Status) {
		s.MissedPongs = missed
	})
}

// RecordUnhealthy bumps the unhealthy-event count and stamps the time.
func (h *HealthTracker) RecordUnhealthy(missed int) {
	h.update(func(s *control.Status) {
		s.MissedPongs = missed
		s.UnhealthyEvents++
		s.LastUnhealthy = time.Now()
	})
}

// RecordReconnect bumps the reconnect counter.
func (h *HealthTracker) RecordReconnect() {
	h.update(func(s *control.Status) {
		s.Reconnects++
	})
}

func (h *HealthTracker) update(mutate func(*control.Status)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	mutate(&h.status)
	snapshot := h.status
	h.mu.Unlock()
	h.notify(snapshot)
}
