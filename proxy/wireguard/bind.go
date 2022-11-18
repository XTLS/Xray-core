package wireguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/wireguard-go/conn"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type netReadInfo struct {
	// status
	lock sync.Mutex
	// param
	buff []byte
	// result
	bytes    int
	endpoint conn.Endpoint
	err      error
}

type netBind struct {
	workers     int
	dialer      internet.Dialer
	connections map[conn.Endpoint]net.Conn

	readQueue chan *netReadInfo
}

func (*netBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return asEndpoint(e), err
}

func (bind *netBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.connections = make(map[conn.Endpoint]net.Conn)
	bind.readQueue = make(chan *netReadInfo)

	fun := func(buff []byte) (cap int, ep conn.Endpoint, err error) {
		defer func() {
			if r := recover(); r != nil {
				cap = 0
				ep = nil
				err = errors.New("channel closed")
			}
		}()

		r := &netReadInfo{
			buff: buff,
		}
		r.lock.Lock()
		bind.readQueue <- r
		r.lock.Lock()
		// fucking dumb way
		r.lock.Unlock()
		return r.bytes, r.endpoint, r.err
	}
	workers := bind.workers
	if workers <= 0 {
		workers = 1
	}
	arr := make([]conn.ReceiveFunc, workers)
	for i := 0; i < workers; i++ {
		arr[i] = fun
	}

	return arr, uint16(uport), nil
}

func (bind *netBind) Close() error {
	bind.connections = nil
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

func (bind *netBind) connectTo(addrPort netip.AddrPort, endpoint conn.Endpoint) (net.Conn, error) {
	addr := addrPort.Addr()
	var ip xnet.Address
	if addr.Is4() {
		ip4 := addr.As4()
		ip = xnet.IPAddress(ip4[:])
	} else {
		ip6 := addr.As16()
		ip = xnet.IPAddress(ip6[:])
	}

	dst := xnet.Destination{
		Address: ip,
		Port:    xnet.Port(addrPort.Port()),
		Network: xnet.Network_UDP,
	}
	c, err := bind.dialer.Dial(context.Background(), dst)
	if err != nil {
		return nil, err
	}
	bind.connections[endpoint] = c

	go func(readQueue <-chan *netReadInfo, endpoint conn.Endpoint) {
		for {
			v, ok := <-readQueue
			if !ok {
				return
			}
			i, err := c.Read(v.buff)
			v.bytes = i
			v.endpoint = endpoint
			v.err = err
			v.lock.Unlock()
			if err != nil && errors.Is(err, io.EOF) {
				delete(bind.connections, endpoint)
				return
			}
		}
	}(bind.readQueue, endpoint)

	return c, nil
}

func (bind *netBind) Send(buff []byte, endpoint conn.Endpoint) error {
	if bind.connections == nil {
		return newError("bind not be open yet")
	}

	var err error

	uconn, ok := bind.connections[endpoint]
	if !ok {
		nend, ok := endpoint.(StdNetEndpoint)
		if !ok {
			return conn.ErrWrongEndpointType
		}
		addrPort := netip.AddrPort(nend)

		uconn, err = bind.connectTo(addrPort, endpoint)
		if err != nil {
			return err
		}
	}

	_, err = uconn.Write(buff)

	return err
}

func (bind *netBind) SetMark(mark uint32) error {
	return nil
}

type StdNetEndpoint netip.AddrPort

func (StdNetEndpoint) ClearSrc() {}

func (e StdNetEndpoint) DstIP() netip.Addr {
	return (netip.AddrPort)(e).Addr()
}

func (e StdNetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not supported
}

func (e StdNetEndpoint) DstToBytes() []byte {
	b, _ := (netip.AddrPort)(e).MarshalBinary()
	return b
}

func (e StdNetEndpoint) DstToString() string {
	return (netip.AddrPort)(e).String()
}

func (e StdNetEndpoint) SrcToString() string {
	return ""
}

// endpointPool contains a re-usable set of mapping from netip.AddrPort to Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an Endpoint allocates,
// but Endpoints are immutable, so we can re-use them.
var endpointPool = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]conn.Endpoint)
	},
}

// asEndpoint returns an Endpoint containing ap.
func asEndpoint(ap netip.AddrPort) conn.Endpoint {
	m := endpointPool.Get().(map[netip.AddrPort]conn.Endpoint)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = conn.Endpoint(StdNetEndpoint(ap))
		m[ap] = e
	}
	return e
}
