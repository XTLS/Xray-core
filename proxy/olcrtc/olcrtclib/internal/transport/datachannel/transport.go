// Package datachannel provides a transport backed by a carrier's data channel.
package datachannel

import (
	"context"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine"
	enginebuiltin "github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/engine/builtin"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/transport"
	"github.com/pion/webrtc/v4"
)

const defaultMaxPayloadSize = 12 * 1024

// ErrByteStreamUnsupported is returned when a carrier engine cannot expose a byte stream.
var ErrByteStreamUnsupported = errors.New("engine does not support byte stream")

type streamTransport struct {
	session engine.Session
}

// New creates a datachannel transport backed by a carrier engine.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	sess, err := enginebuiltin.Open(ctx, cfg.Carrier, enginebuiltin.Config{
		RoomURL:             cfg.RoomURL,
		Name:                cfg.Name,
		OnData:              cfg.OnData,
		OnPeerData:          cfg.OnPeerData,
		DNSServer:           cfg.DNSServer,
		ProxyAddr:           cfg.ProxyAddr,
		ProxyPort:           cfg.ProxyPort,
		Engine:              cfg.Engine,
		URL:                 cfg.URL,
		Token:               cfg.Token,
		AuthToken:           cfg.AuthToken,
		RequireTargetedPeer: cfg.RequireTargetedPeer,
	})
	if err != nil {
		return nil, fmt.Errorf("open engine session: %w", err)
	}

	if !sess.Capabilities().ByteStream {
		_ = sess.Close()
		return nil, ErrByteStreamUnsupported
	}

	return &streamTransport{session: sess}, nil
}

// Connect starts the transport connection.
func (p *streamTransport) Connect(ctx context.Context) error {
	if err := p.session.Connect(ctx); err != nil {
		return fmt.Errorf("session connect: %w", err)
	}
	return nil
}

// Send transmits data through the transport.
func (p *streamTransport) Send(data []byte) error {
	if err := p.session.Send(data); err != nil {
		return fmt.Errorf("session send: %w", err)
	}
	return nil
}

// SendTo transmits data to a specific remote endpoint when the engine supports it.
func (p *streamTransport) SendTo(peerID string, data []byte) error {
	peer, ok := p.session.(engine.PeerSession)
	if !ok {
		return p.Send(data)
	}
	if err := peer.SendTo(peerID, data); err != nil {
		return fmt.Errorf("session send to peer: %w", err)
	}
	return nil
}

// SupportsPeerRouting reports whether this transport can address individual peers.
func (p *streamTransport) SupportsPeerRouting() bool {
	_, ok := p.session.(engine.PeerSession)
	return ok
}

// Close terminates the transport.
func (p *streamTransport) Close() error {
	if err := p.session.Close(); err != nil {
		return fmt.Errorf("session close: %w", err)
	}
	return nil
}

// ResetPeer clears peer binding on engines that expose it.
func (p *streamTransport) ResetPeer() {
	if resetter, ok := p.session.(interface{ ResetPeer() }); ok {
		resetter.ResetPeer()
	}
}

// Reconnect forwards to the underlying engine session.
func (p *streamTransport) Reconnect(reason string) { p.session.Reconnect(reason) }

// SetReconnectCallback registers reconnect handling.
func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.session.SetReconnectCallback(func(*webrtc.DataChannel) {
		if cb != nil {
			cb()
		}
	})
}

// SetShouldReconnect configures reconnect policy.
func (p *streamTransport) SetShouldReconnect(fn func() bool) {
	p.session.SetShouldReconnect(fn)
}

// SetEndedCallback registers end-of-session handling.
func (p *streamTransport) SetEndedCallback(cb func(string)) {
	p.session.SetEndedCallback(cb)
}

// WatchConnection monitors connection lifecycle.
func (p *streamTransport) WatchConnection(ctx context.Context) {
	p.session.WatchConnection(ctx)
}

// CanSend reports whether transport is ready for sending.
func (p *streamTransport) CanSend() bool {
	return p.session.CanSend()
}

// WaitForPeer blocks until the remote peer is confirmed ready, or ctx expires.
// Implements transport.PeerReadyTransport.
func (p *streamTransport) WaitForPeer(ctx context.Context) error {
	waiter, ok := p.session.(engine.PeerReadySession)
	if !ok {
		return nil
	}
	if err := waiter.WaitForPeer(ctx); err != nil {
		return fmt.Errorf("wait for peer: %w", err)
	}
	return nil
}

// Features describes the current datachannel transport semantics.
func (p *streamTransport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  defaultMaxPayloadSize,
	}
}
