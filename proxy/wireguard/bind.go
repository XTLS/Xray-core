package wireguard

import (
	"context"
	"net/netip"
	"strconv"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type netReadInfo struct {
	buff     []byte
	endpoint conn.Endpoint
}

// reduce duplicated code
type netBind struct {
	dns       dns.Client
	dnsOption dns.IPOption

	workers   int
	readQueue chan *netReadInfo
}

// SetMark implements conn.Bind
func (bind *netBind) SetMark(mark uint32) error {
	return nil
}

// ParseEndpoint implements conn.Bind
func (n *netBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ipStr, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	addr := net.ParseAddress(ipStr)
	if addr.Family() == net.AddressFamilyDomain {
		ips, _, err := n.dns.LookupIP(addr.Domain(), n.dnsOption)
		if err != nil {
			return nil, err
		} else if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		addr = net.IPAddress(ips[0])
	}

	dst := net.Destination{
		Address: addr,
		Port:    net.Port(portNum),
		Network: net.Network_UDP,
	}

	return &netEndpoint{
		dst: dst,
	}, nil
}

// BatchSize implements conn.Bind
func (bind *netBind) BatchSize() int {
	return 1
}

// Open implements conn.Bind
func (bind *netBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.readQueue = make(chan *netReadInfo)

	fun := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		r, ok := <-bind.readQueue
		if !ok {
			return 0, errors.New("channel closed")
		}
		copy(bufs[0], r.buff)
		sizes[0], eps[0] = len(r.buff), r.endpoint
		return 1, nil
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

// Close implements conn.Bind
func (bind *netBind) Close() error {
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

type netBindClient struct {
	netBind

	ctx      context.Context
	dialer   internet.Dialer
	reserved []byte
}

func (bind *netBindClient) connectTo(endpoint *netEndpoint) error {
	c, err := bind.dialer.Dial(bind.ctx, endpoint.dst)
	if err != nil {
		return err
	}
	endpoint.conn = c

	go func(readQueue chan<- *netReadInfo, endpoint *netEndpoint) {
		defer func() {
			if r := recover(); r != nil {
				errors.LogInfo(context.Background(), "channel closed")
			}
		}()

		for {
			buff := make([]byte, device.MaxMessageSize)
			n, err := c.Read(buff)

			if err != nil {
				endpoint.conn = nil
				return
			}

			if n > 3 {
				buff[1] = 0
				buff[2] = 0
				buff[3] = 0
			}

			readQueue <- &netReadInfo{
				buff:     buff[:n],
				endpoint: endpoint,
			}
		}
	}(bind.readQueue, endpoint)

	return nil
}

func (bind *netBindClient) Send(buff [][]byte, endpoint conn.Endpoint) error {
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

	for _, buff := range buff {
		if len(buff) > 3 && len(bind.reserved) == 3 {
			copy(buff[1:], bind.reserved)
		}
		if _, err = nend.conn.Write(buff); err != nil {
			return err
		}
	}
	return nil
}

type netBindServer struct {
	netBind
}

func (bind *netBindServer) Send(buff [][]byte, endpoint conn.Endpoint) error {
	var err error

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	if nend.conn == nil {
		return errors.New("connection not open yet")
	}

	for _, buff := range buff {
		if _, err = nend.conn.Write(buff); err != nil {
			return err
		}
	}

	return err
}

type netEndpoint struct {
	dst  net.Destination
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
	var dat []byte
	if e.dst.Address.Family().IsIPv4() {
		dat = e.dst.Address.IP().To4()[:]
	} else {
		dat = e.dst.Address.IP().To16()[:]
	}
	dat = append(dat, byte(e.dst.Port), byte(e.dst.Port>>8))
	return dat
}

func (e netEndpoint) DstToString() string {
	return e.dst.NetAddr()
}

func (e netEndpoint) SrcToString() string {
	return ""
}

func toNetIpAddr(addr net.Address) netip.Addr {
	if addr.Family().IsIPv4() {
		ip := addr.IP()
		return netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	} else {
		ip := addr.IP()
		arr := [16]byte{}
		for i := 0; i < 16; i++ {
			arr[i] = ip[i]
		}
		return netip.AddrFrom16(arr)
	}
}
