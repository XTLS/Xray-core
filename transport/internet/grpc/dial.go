package grpc

import (
	"context"
	gonet "net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	newError("creating connection to ", dest).WriteToLog(session.ExportIDToError(ctx))

	conn, err := dialgRPC(ctx, dest, streamSettings)
	if err != nil {
		return nil, newError("failed to dial gRPC").Base(err)
	}
	return internet.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type dialerConf struct {
	net.Destination
	*internet.SocketConfig
	*tls.Config
}

var (
	globalDialerMap    map[dialerConf]*grpc.ClientConn
	globalDialerAccess sync.Mutex
)

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)

	conn, err := getGrpcClient(ctx, dest, tlsConfig, streamSettings.SocketSettings)

	if err != nil {
		return nil, newError("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(conn)
	if grpcSettings.MultiMode {
		newError("using gRPC multi mode").AtDebug().WriteToLog()
		grpcService, err := client.(encoding.GRPCServiceClientX).TunMultiCustomName(ctx, grpcSettings.ServiceName)
		if err != nil {
			return nil, newError("Cannot dial gRPC").Base(err)
		}
		return encoding.NewMultiHunkConn(grpcService, nil), nil
	}

	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(ctx, grpcSettings.ServiceName)
	if err != nil {
		return nil, newError("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, nil), nil
}

func getGrpcClient(ctx context.Context, dest net.Destination, tlsConfig *tls.Config, sockopt *internet.SocketConfig) (*grpc.ClientConn, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*grpc.ClientConn)
	}

	if client, found := globalDialerMap[dialerConf{dest, sockopt, tlsConfig}]; found && client.GetState() != connectivity.Shutdown {
		return client, nil
	}

	dialOption := grpc.WithInsecure()

	if tlsConfig != nil {
		dialOption = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.GetTLSConfig()))
	}

	conn, err := grpc.Dial(
		gonet.JoinHostPort(dest.Address.String(), dest.Port.String()),
		dialOption,
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithContextDialer(func(gctx context.Context, s string) (gonet.Conn, error) {
			gctx = session.ContextWithID(gctx, session.IDFromContext(ctx))
			gctx = session.ContextWithOutbound(gctx, session.OutboundFromContext(ctx))

			rawHost, rawPort, err := net.SplitHostPort(s)
			select {
			case <-gctx.Done():
				return nil, gctx.Err()
			default:
			}

			if err != nil {
				return nil, err
			}
			if len(rawPort) == 0 {
				rawPort = "443"
			}
			port, err := net.PortFromString(rawPort)
			if err != nil {
				return nil, err
			}
			address := net.ParseAddress(rawHost)
			return internet.DialSystem(gctx, net.TCPDestination(address, port), sockopt)
		}),
	)
	globalDialerMap[dialerConf{dest, sockopt, tlsConfig}] = conn
	return conn, err
}
