// Package proxy contains all proxies used by Xray.
//
// To implement an inbound or outbound proxy, one needs to do the following:
// 1. Implement the interface(s) below.
// 2. Register a config creator through common.RegisterConfig.
package proxy

import (
	"context"
	gotls "crypto/tls"
	"io"
	"runtime"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// An Inbound processes inbound connections.
type Inbound interface {
	// Network returns a list of networks that this inbound supports. Connections with not-supported networks will not be passed into Process().
	Network() []net.Network

	// Process processes a connection of given network. If necessary, the Inbound can dispatch the connection to an Outbound.
	Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
}

// An Outbound process outbound connections.
type Outbound interface {
	// Process processes the given connection. The given dialer may be used to dial a system outbound connection.
	Process(context.Context, *transport.Link, internet.Dialer) error
}

// UserManager is the interface for Inbounds and Outbounds that can manage their users.
type UserManager interface {
	// AddUser adds a new user.
	AddUser(context.Context, *protocol.MemoryUser) error

	// RemoveUser removes a user by email.
	RemoveUser(context.Context, string) error
}

type GetInbound interface {
	GetInbound() Inbound
}

type GetOutbound interface {
	GetOutbound() Outbound
}

// UnwrapRawConn support unwrap stats, tls, utls, reality and proxyproto conn and get raw tcp conn from it
func UnwrapRawConn(conn net.Conn) (net.Conn, stats.Counter, stats.Counter) {
	var readCounter, writerCounter stats.Counter
	if conn != nil {
		statConn, ok := conn.(*stat.CounterConnection)
		if ok {
			conn = statConn.Connection
			readCounter = statConn.ReadCounter
			writerCounter = statConn.WriteCounter
		}
		if xc, ok := conn.(*gotls.Conn); ok {
			conn = xc.NetConn()
		} else if utlsConn, ok := conn.(*tls.UConn); ok {
			conn = utlsConn.NetConn()
		} else if realityConn, ok := conn.(*reality.Conn); ok {
			conn = realityConn.NetConn()
		} else if realityUConn, ok := conn.(*reality.UConn); ok {
			conn = realityUConn.NetConn()
		}
		if pc, ok := conn.(*proxyproto.Conn); ok {
			conn = pc.Raw()
			// 8192 > 4096, there is no need to process pc's bufReader
		}
	}
	return conn, readCounter, writerCounter
}

// CopyRawConnIfExist use the most efficient copy method.
// - If caller don't want to turn on splice, do not pass in both reader conn and writer conn
// - writer are from *transport.Link
func CopyRawConnIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer signal.ActivityUpdater) error {
	readerConn, readCounter, _ := UnwrapRawConn(readerConn)
	writerConn, _, writeCounter := UnwrapRawConn(writerConn)
	reader := buf.NewReader(readerConn)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if tc, ok := writerConn.(*net.TCPConn); ok && readerConn != nil && writerConn != nil && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
			for inbound.CanSpliceCopy != 3 {
				if inbound.CanSpliceCopy == 1 {
					newError("CopyRawConn splice").WriteToLog(session.ExportIDToError(ctx))
					runtime.Gosched() // necessary
					w, err := tc.ReadFrom(readerConn)
					if readCounter != nil {
						readCounter.Add(w)
					}
					if writeCounter != nil {
						writeCounter.Add(w)
					}
					if err != nil && errors.Cause(err) != io.EOF {
						return err
					}
					return nil
				}
				buffer, err := reader.ReadMultiBuffer()
				if !buffer.IsEmpty() {
					if readCounter != nil {
						readCounter.Add(int64(buffer.Len()))
					}
					timer.Update()
					if werr := writer.WriteMultiBuffer(buffer); werr != nil {
						return werr
					}
				}
				if err != nil {
					return err
				}
			}
		}
	}
	newError("CopyRawConn readv").WriteToLog(session.ExportIDToError(ctx))
	if err := buf.Copy(reader, writer, buf.UpdateActivity(timer), buf.AddToStatCounter(readCounter)); err != nil {
		return newError("failed to process response").Base(err)
	}
	return nil
}
