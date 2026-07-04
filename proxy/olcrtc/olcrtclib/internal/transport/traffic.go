package transport

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// ErrTrafficPayloadTooLarge is returned when Send receives a payload above the configured cap.
var ErrTrafficPayloadTooLarge = errors.New("traffic payload exceeds max_payload_size")

var (
	errTrafficConnect = errors.New("traffic connect failed")
	errTrafficSend    = errors.New("traffic send failed")
	errTrafficClose   = errors.New("traffic close failed")
)

type trafficTransport struct {
	inner          Transport
	maxPayloadSize int
	minDelay       time.Duration
	maxDelay       time.Duration
	sendMu         sync.Mutex
}

// WithTraffic wraps tr with optional payload caps and send pacing.
func WithTraffic(tr Transport, cfg TrafficConfig) Transport {
	if tr == nil {
		return nil
	}
	cfg = effectiveTrafficConfig(tr.Features(), cfg)
	if cfg.MaxPayloadSize <= 0 && cfg.MinDelay <= 0 && cfg.MaxDelay <= 0 {
		return tr
	}
	return &trafficTransport{
		inner:          tr,
		maxPayloadSize: cfg.MaxPayloadSize,
		minDelay:       cfg.MinDelay,
		maxDelay:       cfg.MaxDelay,
	}
}

func effectiveTrafficConfig(features Features, cfg TrafficConfig) TrafficConfig {
	if cfg.MaxPayloadSize > 0 && features.MaxPayloadSize > 0 && features.MaxPayloadSize < cfg.MaxPayloadSize {
		cfg.MaxPayloadSize = features.MaxPayloadSize
	}
	return cfg
}

func (t *trafficTransport) Connect(ctx context.Context) error {
	if err := t.inner.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %w", errTrafficConnect, err)
	}
	return nil
}

func (t *trafficTransport) Send(data []byte) error {
	return t.sendWith(func(payload []byte) error {
		return t.inner.Send(payload)
	}, data)
}

func (t *trafficTransport) SendTo(peerID string, data []byte) error {
	peer, ok := t.inner.(PeerTransport)
	if !ok || !peer.SupportsPeerRouting() {
		return t.Send(data)
	}
	return t.sendWith(func(payload []byte) error {
		return peer.SendTo(peerID, payload)
	}, data)
}

func (t *trafficTransport) SupportsPeerRouting() bool {
	peer, ok := t.inner.(PeerTransport)
	return ok && peer.SupportsPeerRouting()
}

func (t *trafficTransport) sendWith(send func([]byte) error, data []byte) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if t.maxPayloadSize > 0 && len(data) > t.maxPayloadSize {
		return fmt.Errorf("%w: size=%d max=%d", ErrTrafficPayloadTooLarge, len(data), t.maxPayloadSize)
	}
	if delay := t.nextDelay(); delay > 0 {
		time.Sleep(delay)
	}
	if err := send(data); err != nil {
		return fmt.Errorf("%w: %w", errTrafficSend, err)
	}
	return nil
}

func (t *trafficTransport) Close() error {
	if err := t.inner.Close(); err != nil {
		return fmt.Errorf("%w: %w", errTrafficClose, err)
	}
	return nil
}

func (t *trafficTransport) ResetPeer() {
	if resetter, ok := t.inner.(interface{ ResetPeer() }); ok {
		resetter.ResetPeer()
	}
}

func (t *trafficTransport) Reconnect(reason string) { t.inner.Reconnect(reason) }

func (t *trafficTransport) SetReconnectCallback(cb func()) { t.inner.SetReconnectCallback(cb) }

func (t *trafficTransport) SetShouldReconnect(fn func() bool) { t.inner.SetShouldReconnect(fn) }

func (t *trafficTransport) SetEndedCallback(cb func(string)) { t.inner.SetEndedCallback(cb) }

func (t *trafficTransport) WatchConnection(ctx context.Context) { t.inner.WatchConnection(ctx) }

func (t *trafficTransport) CanSend() bool { return t.inner.CanSend() }

func (t *trafficTransport) Features() Features {
	features := t.inner.Features()
	if t.maxPayloadSize > 0 &&
		(features.MaxPayloadSize == 0 || t.maxPayloadSize < features.MaxPayloadSize) {
		features.MaxPayloadSize = t.maxPayloadSize
	}
	return features
}

func (t *trafficTransport) nextDelay() time.Duration {
	if t.maxDelay <= 0 && t.minDelay <= 0 {
		return 0
	}
	minDelay := t.minDelay
	maxDelay := t.maxDelay
	if maxDelay <= minDelay {
		return minDelay
	}
	return minDelay + time.Duration(rand.Int64N(int64(maxDelay-minDelay))) //nolint:gosec,lll // G404: non-cryptographic pacing jitter
}
