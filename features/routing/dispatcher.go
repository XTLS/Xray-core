package routing

import (
	"context"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/exchange"
)

// Dispatcher is a feature that dispatches inbound requests to outbound handlers based on rules.
// Dispatcher is required to be registered in a Xray instance to make Xray function properly.
//
// xray:api:stable
type Dispatcher interface {
	features.Feature

	// Dispatch returns a Ray for transporting data for the given request.
	Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error)
	DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error
}

// StreamDispatcher admits a decoded logical stream without a Link. It is kept
// separate from Dispatcher so existing packet and API entrances remain intact.
type StreamDispatcher interface {
	DispatchStream(ctx context.Context, dest net.Destination, source exchange.Stream) error
}

// PacketDispatcher admits a decoded UDP association with its first target.
type PacketDispatcher interface {
	DispatchPacket(context.Context, net.Destination, exchange.PacketEndpoint) error
}

func DispatchPacket(dispatcher Dispatcher, ctx context.Context, first net.Destination, source exchange.PacketEndpoint) error {
	if native, ok := dispatcher.(PacketDispatcher); ok {
		return native.DispatchPacket(ctx, first, source)
	}
	return errors.New("packet admission unavailable on dispatcher")
}

// DispatchStream uses native admission when available. The projection is only
// for existing third-party Dispatcher implementations until they opt into the
// decoded stream boundary; built-in selected entrances implement it directly.
func DispatchStream(dispatcher Dispatcher, ctx context.Context, dest net.Destination, source exchange.Stream) error {
	if native, ok := dispatcher.(StreamDispatcher); ok {
		return native.DispatchStream(ctx, dest, source)
	}
	return dispatcher.DispatchLink(ctx, dest, &transport.Link{Reader: buf.NewReader(source.ProjectReader()), Writer: buf.NewWriter(source.ProjectWriter())})
}

// DispatcherType returns the type of Dispatcher interface. Can be used to implement common.HasType.
//
// xray:api:stable
func DispatcherType() interface{} {
	return (*Dispatcher)(nil)
}
