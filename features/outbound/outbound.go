package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
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

// StreamHandler prepares and executes a decoded logical stream.
type StreamHandler interface {
	DispatchStream(context.Context, exchange.Stream) error
}

type PacketHandler interface {
	PreparePacket(context.Context) (exchange.PacketEndpoint, error)
}

// DispatchStream keeps unconverted custom handlers reachable through their
// old Link entry. Selected built-in handlers implement StreamHandler.
func DispatchStream(handler Handler, ctx context.Context, source exchange.Stream) error {
	if native, ok := handler.(StreamHandler); ok {
		return native.DispatchStream(ctx, source)
	}
	handler.Dispatch(ctx, &transport.Link{Reader: buf.NewReader(source.ProjectReader()), Writer: buf.NewWriter(source.ProjectWriter())})
	return nil
}

type HandlerSelector interface {
	Select([]string) []string
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
