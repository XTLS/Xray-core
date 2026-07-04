// Package transport defines transport abstractions and registry.
//
// A transport encodes byte payloads onto a carrier (engine) primitive - either
// a reliable byte stream (datachannel) or a video track (videochannel,
// seichannel, vp8channel). Transport-specific tuning lives in per-transport
// Options types; the common configuration shared by every transport lives in
// [Config].
package transport

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrTransportNotFound is returned when a requested transport is not registered.
var ErrTransportNotFound = errors.New("transport not found")

// ErrOptionsTypeMismatch is returned when a transport receives options of the wrong type.
var ErrOptionsTypeMismatch = errors.New("transport options type mismatch")

// Features describes the delivery semantics of a transport.
type Features struct {
	Reliable        bool
	Ordered         bool
	MessageOriented bool
	MaxPayloadSize  int
}

// Transport defines a byte transport independent of the underlying carrier.
type Transport interface {
	Connect(ctx context.Context) error
	Send(data []byte) error
	Close() error
	SetReconnectCallback(cb func())
	SetShouldReconnect(fn func() bool)
	SetEndedCallback(cb func(string))
	WatchConnection(ctx context.Context)
	CanSend() bool
	Features() Features
	// Reconnect asks the underlying carrier (engine) to tear down and
	// re-establish the SFU connection. Upper layers call this when a
	// liveness probe declares the link dead - useful when the engine has
	// not yet noticed silent packet loss.
	Reconnect(reason string)
}

// ControlPlane is implemented by transports that can route control-plane
// traffic independently of the bulk data plane. When a transport implements
// this interface, callers should use ControlSend/ControlOnData for the first
// smux stream (the olcrtc control/handshake stream) so that it does not
// compete with bulk data in the same KCP send buffer.
type ControlPlane interface {
	// ControlSend sends a raw encrypted frame on the control-plane channel.
	ControlSend(data []byte) error
	// SetControlOnData registers the callback invoked for every frame
	// received on the control-plane channel.
	SetControlOnData(cb func([]byte))
	// ControlCanSend reports whether the control-plane is ready to send.
	// Unlike CanSend, this should return true as soon as the subscriber PC
	// is connected — it does NOT require the publisher PC to be ready.
	ControlCanSend() bool
}

// PeerTransport is implemented by transports whose carrier can identify and
// address individual remote endpoints.
type PeerTransport interface {
	Transport
	SendTo(peerID string, data []byte) error
	SupportsPeerRouting() bool
}

// PeerControlPlane is implemented by transports that support per-peer isolated
// control planes. Each peer identified by peerID gets its own KCP session so
// that multiple clients can handshake and maintain liveness independently.
// The server uses this to create per-peer smux control sessions.
type PeerControlPlane interface {
	// ControlSendTo sends a control frame to a specific peer.
	ControlSendTo(peerID string, data []byte) error
	// SetControlOnPeerData registers the callback invoked when a control frame
	// arrives for any peer. peerID is the hex data-epoch string.
	SetControlOnPeerData(cb func(peerID string, data []byte))
	// ControlPeerCanSend reports whether the control plane for a specific peer
	// is ready to send.
	ControlPeerCanSend(peerID string) bool
}

// PeerReadyTransport is implemented by transports whose carrier can signal
// when a remote peer has appeared. WaitForPeer blocks until the remote side
// is confirmed ready (first epoch frame received), or ctx is cancelled.
type PeerReadyTransport interface {
	WaitForPeer(ctx context.Context) error
}

// Options is a marker for per-transport option structs. Each transport package
// defines its own Options type (e.g. videochannel.Options) and registers a
// factory that consumes it via type assertion. A nil Options is valid for
// transports that need no extra configuration (e.g. datachannel).
type Options interface {
	TransportOptions()
}

// TrafficConfig controls optional reliability-oriented send shaping.
type TrafficConfig struct {
	MaxPayloadSize int
	MinDelay       time.Duration
	MaxDelay       time.Duration
}

// Config holds common transport configuration applicable to every transport.
type Config struct {
	// Carrier is the auth-provider name; engine/URL/token are resolved through it.
	Carrier string
	RoomURL string
	// Engine, URL, Token are forwarded to carrier.Config for the "none" auth
	// carrier (direct engine access without a service-specific auth flow).
	Engine string
	URL    string
	Token  string
	// AuthToken is an optional pre-issued account token forwarded to the auth
	// provider (e.g. a WB Stream account token). Empty uses the provider's
	// default guest flow.
	AuthToken  string
	ChannelID  string
	DeviceID   string
	Name       string
	OnData     func([]byte)
	OnPeerData func(peerID string, data []byte)
	DNSServer  string
	ProxyAddr  string
	ProxyPort  int

	// RequireTargetedPeer makes single-peer engines ignore broadcast frames
	// from unrelated olcrtc clients until a peer sends a frame addressed to
	// this session's local epoch. Server-side transports leave this disabled
	// so they can accept initial broadcast CLIENT_HELLO frames.
	RequireTargetedPeer bool

	// Options carries transport-specific tuning. Type is per-transport-package.
	Options Options

	// Traffic controls payload-size and pacing shaping applied around the
	// underlying transport's Send.
	Traffic TrafficConfig
}

// Factory creates a transport instance.
type Factory func(ctx context.Context, cfg Config) (Transport, error)

var registry = make(map[string]Factory) //nolint:gochecknoglobals // package-level state intentional

// Register adds a transport factory to the registry.
func Register(name string, factory Factory) {
	registry[name] = factory
}

// New creates a transport instance by name.
func New(ctx context.Context, name string, cfg Config) (Transport, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrTransportNotFound, name)
	}
	tr, err := factory(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return WithTraffic(tr, cfg.Traffic), nil
}

// Available returns a list of registered transport names.
func Available() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
