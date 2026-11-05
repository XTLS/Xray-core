package outbound

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
)

// Handler is the interface for handlers that process outbound connections.
//
// xray:api:stable
type Handler interface {
	common.Runnable
	Tag() string
	Dispatch(ctx context.Context, link *transport.Link)
	SenderSettings() *serial.TypedMessage
	ProxySettings() *serial.TypedMessage
}

type HandlerSelector interface {
	Select([]string) []string
}

// ProbeTagPrefix is reserved for temporary outbounds created by the
// ProbeOutbound API for the duration of one check. Such outbounds are never
// returned by HandlerSelector.Select, so observatories and balancers do not
// pick them up, and are hidden from the ListOutbounds API.
const ProbeTagPrefix = "xdprobe-"

// IsProbeTag reports whether tag belongs to a temporary probe outbound.
func IsProbeTag(tag string) bool {
	return strings.HasPrefix(tag, ProbeTagPrefix)
}

// Manager is a feature that manages outbound.Handlers.
//
// xray:api:stable
type Manager interface {
	features.Feature
	// GetHandler returns an outbound.Handler for the given tag.
	GetHandler(tag string) Handler
	// GetDefaultHandler returns the default outbound.Handler. It is usually the first outbound.Handler specified in the configuration.
	GetDefaultHandler() Handler
	// AddHandler adds a handler into this outbound.Manager.
	AddHandler(ctx context.Context, handler Handler) error

	// RemoveHandler removes a handler from outbound.Manager.
	RemoveHandler(ctx context.Context, tag string) error

	// ListHandlers returns a list of outbound.Handler.
	ListHandlers(ctx context.Context) []Handler
}

// ManagerType returns the type of Manager interface. Can be used to implement common.HasType.
//
// xray:api:stable
func ManagerType() interface{} {
	return (*Manager)(nil)
}
