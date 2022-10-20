package grpc

import (
	"context"
	gonet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	newError("creating connection to ", dest).WriteToLog(session.ExportIDToError(ctx))

	conn, err := dialgRPC(ctx, dest, streamSettings)
	if err != nil {
		return nil, newError("failed to dial gRPC").Base(err)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]*grpc.ClientConn
	globalDialerAccess sync.Mutex
)

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	conn, err := getGrpcClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, newError("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(conn)
	if grpcSettings.MultiMode {
		newError("using gRPC multi mode").AtDebug().WriteToLog()
		grpcService, err := client.(encoding.GRPCServiceClientX).TunMultiCustomName(ctx, grpcSettings.getNormalizedName())
		if err != nil {
			return nil, newError("Cannot dial gRPC").Base(err)
		}
		return encoding.NewMultiHunkConn(grpcService, nil), nil
	}

	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(ctx, grpcSettings.getNormalizedName())
	if err != nil {
		return nil, newError("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, nil), nil
}

func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*grpc.ClientConn, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*grpc.ClientConn)
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	sockopt := streamSettings.SocketSettings
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found && client.GetState() != connectivity.Shutdown {
		return client, nil
	}

	dialOptions := []grpc.DialOption{
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
	}

	if tlsConfig != nil {
		var transportCredential credentials.TransportCredentials
		if fingerprint, exists := tls.Fingerprints[tlsConfig.Fingerprint]; exists {
			transportCredential = tls.NewGrpcUtls(tlsConfig.GetTLSConfig(), fingerprint)
		} else { // Fallback to normal gRPC TLS
			transportCredential = credentials.NewTLS(tlsConfig.GetTLSConfig())
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(transportCredential))
	} else {
		dialOptions = append(dialOptions, grpc.WithInsecure())
	}

	if grpcSettings.IdleTimeout > 0 || grpcSettings.HealthCheckTimeout > 0 || grpcSettings.PermitWithoutStream {
		dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * time.Duration(grpcSettings.IdleTimeout),
			Timeout:             time.Second * time.Duration(grpcSettings.HealthCheckTimeout),
			PermitWithoutStream: grpcSettings.PermitWithoutStream,
		}))
	}

	if grpcSettings.InitialWindowsSize > 0 {
		dialOptions = append(dialOptions, grpc.WithInitialWindowSize(grpcSettings.InitialWindowsSize))
	}

	var grpcDestHost string
	if dest.Address.Family().IsDomain() {
		grpcDestHost = dest.Address.Domain()
	} else {
		grpcDestHost = dest.Address.IP().String()
	}

	conn, err := grpc.Dial(
		gonet.JoinHostPort(grpcDestHost, dest.Port.String()),
		dialOptions...,
	)
	globalDialerMap[dialerConf{dest, streamSettings}] = conn
	return conn, err
}
