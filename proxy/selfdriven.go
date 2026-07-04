package proxy

import (
	"context"
	"reflect"
)

// SelfDrivenInbound is implemented by inbound proxies that manage their own
// connection source instead of being driven by a socket listener. Such a proxy
// dials out to a carrier (e.g. a WebRTC SFU) and accepts logical connections
// from it, dispatching each through Xray's router. It obtains the dispatcher
// itself (typically via core.RequireFeatures at construction).
//
// The handler manager runs Serve in its own goroutine at start and cancels the
// provided context on close. Serve should block until ctx is done.
type SelfDrivenInbound interface {
	Serve(ctx context.Context) error
}

// selfDrivenInboundConfigs records the proxy config proto types whose handlers
// are self-driven, so the inbound handler manager can pick the self-driven
// handler path without instantiating the proxy first.
var selfDrivenInboundConfigs = make(map[reflect.Type]bool)

// RegisterSelfDrivenInbound marks a proxy config type (e.g. (*ServerConfig)(nil))
// as producing a SelfDrivenInbound. Call from the proxy package's init.
func RegisterSelfDrivenInbound(config interface{}) {
	selfDrivenInboundConfigs[reflect.TypeOf(config)] = true
}

// IsSelfDrivenInbound reports whether the given proxy config's handler is
// self-driven (registered via RegisterSelfDrivenInbound).
func IsSelfDrivenInbound(config interface{}) bool {
	return selfDrivenInboundConfigs[reflect.TypeOf(config)]
}
