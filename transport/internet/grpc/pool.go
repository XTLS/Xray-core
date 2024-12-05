package grpc

import (
	"container/ring"
	"context"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// Factory is a function type creating a grpc client
type Factory func(ctx context.Context, addr net.Destination, cfg *internet.MemoryStreamConfig) (*grpc.ClientConn, error)

type ClientConnInterface interface {
	grpc.ClientConnInterface
}

var _ ClientConnInterface = (*ClientConn)(nil)

type PoolManage struct {
	factory Factory

	// key: dialeConf, value: ringPool
	addrs sync.Map

	mu sync.Mutex
}

func NewPoolManage(factory Factory) *PoolManage {
	pm := &PoolManage{
		factory: factory,
		addrs:   sync.Map{},
	}

	return pm
}

func (pm *PoolManage) GetConn(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*ClientConn, error) {
	connring, ok := pm.addrs.Load(dialerConf{dest, streamSettings})
	if ok {
		nextring := connring.(*ring.Ring).Next()
		conn := nextring.Value.(*ClientConn)
		if conn.GetState() != connectivity.Shutdown {
			if nextring != connring.(*ring.Ring) {
				// update the ring, there are more than one connection
				pm.addrs.Store(dialerConf{dest, streamSettings}, nextring)
			}
			return conn, nil
		}
		var err error
		conn.Lock()
		defer conn.Unlock()
		if conn.GetState() != connectivity.Shutdown {
			return conn, nil
		}
		conn.ClientConn, err = pm.factory(ctx, dest, streamSettings)
		return conn, err
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	connring, ok = pm.addrs.Load(dialerConf{dest, streamSettings})
	if ok {
		return connring.(*ring.Ring).Next().Value.(*ClientConn), nil
	}
	var num int
	if connnum := streamSettings.ProtocolSettings.(*Config).ConnNumber; connnum <= 0 {
		num = 1
	} else {
		num = int(connnum)
	}

	tmpring := ring.New(num)
	for i := 0; i < num; i++ {
		conn, err := pm.factory(ctx, dest, streamSettings)
		if err != nil {
			return nil, err
		}
		tmpring.Value = NewClientConn(conn)
		tmpring = tmpring.Next()
	}
	pm.addrs.Store(dialerConf{dest, streamSettings}, tmpring)
	return tmpring.Value.(*ClientConn), nil
}

// ClientConn is the wrapper for a grpc client conn
type ClientConn struct {
	*grpc.ClientConn

	sync.Mutex
}

func NewClientConn(cc *grpc.ClientConn) *ClientConn {
	return &ClientConn{
		ClientConn: cc,
	}
}
