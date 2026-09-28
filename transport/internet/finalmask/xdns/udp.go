package xdns

import (
	"context"
	goerrors "errors"
	stdnet "net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type udpResolver struct {
	conn stdnet.PacketConn
	addr *stdnet.UDPAddr
}

func (r *udpResolver) send(p []byte) error {
	_, err := r.conn.WriteTo(p, r.addr)
	return err
}

type udpReceiver struct {
	conn      stdnet.PacketConn
	resolvers map[string]*clientResolver
	handle    func(*clientResolver, []byte, stdnet.Addr)
}

func (r *udpReceiver) run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var buf [finalmask.UDPSize]byte
	for {
		n, addr, err := r.conn.ReadFrom(buf[:])
		if err != nil {
			if goerrors.Is(err, stdnet.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		resolver := r.resolvers[addr.String()]
		if resolver == nil {
			continue
		}
		response := make([]byte, n)
		copy(response, buf[:n])
		r.handle(resolver, response, addr)
	}
}

func startUDPReceiver(ctx context.Context, wg *sync.WaitGroup, conn stdnet.PacketConn, resolvers []*clientResolver, handle func(*clientResolver, []byte, stdnet.Addr)) {
	byAddress := make(map[string]*clientResolver, len(resolvers))
	for _, resolver := range resolvers {
		byAddress[resolver.udp.addr.String()] = resolver
	}
	wg.Add(1)
	go (&udpReceiver{conn: conn, resolvers: byAddress, handle: handle}).run(ctx, wg)
}

func logUDPError(addr stdnet.Addr, err error) {
	errors.LogDebug(context.Background(), addr, " xdns udp err ", err)
}
