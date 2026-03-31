package internet

import (
	"context"
	"net"

	"github.com/xtls/xray-core/transport/internet/stat"
)

type transportDatagramContextKey struct{}

// TransportDatagramConn is an optional transport capability that allows
// protocols to switch payload I/O from stream frames to transport datagrams
// after their own headers were exchanged on the stream.
type TransportDatagramConn interface {
	EnableTransportDatagramRead() error
	EnableTransportDatagramWrite() error
}

func ContextWithTransportDatagrams(ctx context.Context, enable bool) context.Context {
	if !enable {
		return ctx
	}
	return context.WithValue(ctx, transportDatagramContextKey{}, struct{}{})
}

func WantTransportDatagrams(ctx context.Context) bool {
	_, ok := ctx.Value(transportDatagramContextKey{}).(struct{})
	return ok
}

func EnableTransportDatagramRead(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if dc, ok := stat.TryUnwrapStatsConn(conn).(TransportDatagramConn); ok {
		return dc.EnableTransportDatagramRead()
	}
	return nil
}

func EnableTransportDatagramWrite(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if dc, ok := stat.TryUnwrapStatsConn(conn).(TransportDatagramConn); ok {
		return dc.EnableTransportDatagramWrite()
	}
	return nil
}
