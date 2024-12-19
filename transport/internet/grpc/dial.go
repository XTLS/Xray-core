package grpc

import (
	"context"
	gonet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)

	conn, err := dialgRPC(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("failed to dial gRPC").Base(err)
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

type globalDialers struct {
	connMap map[dialerConf][]*grpc.ClientConn
}

// getClientConn returns a client connection from the global dialer if the connections already reached the target number
// otherwise return nil
func (d *globalDialers) getClientConn(conf dialerConf) (*grpc.ClientConn, int) {
	if d.connMap == nil {
		d.connMap = make(map[dialerConf][]*grpc.ClientConn)
	}
	if d.connMap[conf] == nil {
		d.connMap[conf] = []*grpc.ClientConn{}
	}

	conns := d.connMap[conf]

	targetConnsNum := conf.MemoryStreamConfig.ProtocolSettings.(*Config).MultiConnections
	if targetConnsNum > int32(len(conns)) {
		return nil, 0
	} else {
		index := dice.Roll(len(conns))
		return conns[index], index
	}
}

// addClientConn adds a client connection to the global dialer
func (d *globalDialers) addClientConn(conf dialerConf, conn *grpc.ClientConn) error {
	if d.connMap == nil {
		d.connMap = make(map[dialerConf][]*grpc.ClientConn)
	}
	if d.connMap[conf] == nil {
		d.connMap[conf] = []*grpc.ClientConn{}
	}

	conns := d.connMap[conf]
	targetConnsNum := conf.MemoryStreamConfig.ProtocolSettings.(*Config).MultiConnections
	if targetConnsNum <= int32(len(conns)) {
		return errors.New("failed to add client connection beacuse reach the limit")
	} else {
		conns = append(conns, conn)
		d.connMap[conf] = conns
		return nil
	}
}

// updateClientConnWithIndex updates a client connection with the given index
// in the case if the clientConn is shutting down, replace it with the new one
func (d *globalDialers) updateClientConnWithIndex(conf dialerConf, conn *grpc.ClientConn, index int) error {
	conns := d.connMap[conf]
	conns[index] = conn
	return nil
}

var (
	globalDialer       globalDialers
	globalDialerAccess sync.Mutex
)

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	conn, err := getGrpcClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(conn)
	if grpcSettings.MultiMode {
		errors.LogDebug(ctx, "using gRPC multi mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunMultiStreamName()+"`")
		grpcService, err := client.(encoding.GRPCServiceClientX).TunMultiCustomName(ctx, grpcSettings.getServiceName(), grpcSettings.getTunMultiStreamName())
		if err != nil {
			return nil, errors.New("Cannot dial gRPC").Base(err)
		}
		return encoding.NewMultiHunkConn(grpcService, nil), nil
	}

	errors.LogDebug(ctx, "using gRPC tun mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunStreamName()+"`")
	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(ctx, grpcSettings.getServiceName(), grpcSettings.getTunStreamName())
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, nil), nil
}

func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*grpc.ClientConn, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)
	sockopt := streamSettings.SocketSettings
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	client, index := globalDialer.getClientConn(dialerConf{dest, streamSettings})
	if client != nil && client.GetState() != connectivity.Shutdown {
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
			select {
			case <-gctx.Done():
				return nil, gctx.Err()
			default:
			}

			rawHost, rawPort, err := net.SplitHostPort(s)
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

			gctx = c.ContextWithID(gctx, c.IDFromContext(ctx))
			gctx = session.ContextWithOutbounds(gctx, session.OutboundsFromContext(ctx))
			gctx = session.ContextWithTimeoutOnly(gctx, true)

			c, err := internet.DialSystem(gctx, net.TCPDestination(address, port), sockopt)
			if err == nil {
				if tlsConfig != nil {
					config := tlsConfig.GetTLSConfig()
					if config.ServerName == "" && address.Family().IsDomain() {
						config.ServerName = address.Domain()
					}
					if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
						return tls.UClient(c, config, fingerprint), nil
					} else { // Fallback to normal gRPC TLS
						return tls.Client(c, config), nil
					}
				}
				if realityConfig != nil {
					return reality.UClient(c, realityConfig, gctx, dest)
				}
			}
			return c, err
		}),
	}

	dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))

	authority := ""
	if grpcSettings.Authority != "" {
		authority = grpcSettings.Authority
	} else if tlsConfig != nil && tlsConfig.ServerName != "" {
		authority = tlsConfig.ServerName
	} else if realityConfig == nil && dest.Address.Family().IsDomain() {
		authority = dest.Address.Domain()
	}
	dialOptions = append(dialOptions, grpc.WithAuthority(authority))

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

	if grpcSettings.UserAgent != "" {
		dialOptions = append(dialOptions, grpc.WithUserAgent(grpcSettings.UserAgent))
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
	if client == nil {
		err := globalDialer.addClientConn(dialerConf{dest, streamSettings}, conn)
		if err != nil {
			return nil, err
		}
	}
	if client != nil && client.GetState() == connectivity.Shutdown {
		globalDialer.updateClientConnWithIndex(dialerConf{dest, streamSettings}, conn, index)
	}
	return conn, err
}
