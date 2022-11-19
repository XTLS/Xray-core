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
	waiter sync.WaitGroup
	// param
	buff []byte
	// result
	bytes    int
	endpoint conn.Endpoint
	err      error
}

type netBind struct {
	workers int
	dialer  internet.Dialer

	readQueue chan *netReadInfo
}

func (*netBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}

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

	return &netEndpoint{
		dst: dst,
	}, nil
}

func (bind *netBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
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
		r.waiter.Add(1)
		bind.readQueue <- r
		r.waiter.Wait() // wait read goroutine done, or we will miss the result
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
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

func (bind *netBind) connectTo(endpoint *netEndpoint) error {
	c, err := bind.dialer.Dial(context.Background(), endpoint.dst)
	if err != nil {
		return err
	}
	endpoint.conn = c

	go func(readQueue <-chan *netReadInfo, endpoint *netEndpoint) {
		for {
			v, ok := <-readQueue
			if !ok {
				return
			}
			i, err := c.Read(v.buff)
			v.bytes = i
			v.endpoint = endpoint
			v.err = err
			v.waiter.Done()
			if err != nil && errors.Is(err, io.EOF) {
				endpoint.conn = nil
				return
			}
		}
	}(bind.readQueue, endpoint)

	return nil
}

func (bind *netBind) Send(buff []byte, endpoint conn.Endpoint) error {
	var err error

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	if nend.conn == nil {
		err = bind.connectTo(nend)
		if err != nil {
			return err
		}
	}

	_, err = nend.conn.Write(buff)

	return err
}

func (bind *netBind) SetMark(mark uint32) error {
	return nil
}

type netEndpoint struct {
	dst  xnet.Destination
	conn net.Conn
}

func (netEndpoint) ClearSrc() {}

func (e netEndpoint) DstIP() netip.Addr {
	return netip.Addr{}
}

func (e netEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e netEndpoint) DstToBytes() []byte {
	return []byte{}
}

func (e netEndpoint) DstToString() string {
	return ""
}

func (e netEndpoint) SrcToString() string {
	return ""
}
