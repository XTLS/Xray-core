package wireguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/sagernet/wireguard-go/conn"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
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

type netBindClient struct {
	workers   int
	dialer    internet.Dialer
	dns       dns.Client
	dnsOption dns.IPOption

	readQueue chan *netReadInfo
}

func (n *netBindClient) ParseEndpoint(s string) (conn.Endpoint, error) {
	ipStr, port, _, err := splitAddrPort(s)
	if err != nil {
		return nil, err
	}

	var addr net.IP
	if IsDomainName(ipStr) {
		ips, err := n.dns.LookupIP(ipStr, n.dnsOption)
		if err != nil {
			return nil, err
		} else if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		addr = ips[0]
	} else {
		addr = net.ParseIP(ipStr)
	}
	if addr == nil {
		return nil, errors.New("failed to parse ip: " + ipStr)
	}

	var ip xnet.Address
	if p4 := addr.To4(); len(p4) == net.IPv4len {
		ip = xnet.IPAddress(p4[:])
	} else {
		ip = xnet.IPAddress(addr[:])
	}

	dst := xnet.Destination{
		Address: ip,
		Port:    xnet.Port(port),
		Network: xnet.Network_UDP,
	}

	return &netEndpoint{
		dst: dst,
	}, nil
}

func (bind *netBindClient) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
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

func (bind *netBindClient) Close() error {
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

func (bind *netBindClient) connectTo(endpoint *netEndpoint) error {
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

func (bind *netBindClient) Send(buff []byte, endpoint conn.Endpoint) error {
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

func (bind *netBindClient) SetMark(mark uint32) error {
	return nil
}

type netEndpoint struct {
	dst  xnet.Destination
	conn net.Conn
}

func (netEndpoint) ClearSrc() {}

func (e netEndpoint) DstIP() netip.Addr {
	return toNetIpAddr(e.dst.Address)
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

func toNetIpAddr(addr xnet.Address) netip.Addr {
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

func stringsLastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func splitAddrPort(s string) (ip string, port uint16, v6 bool, err error) {
	i := stringsLastIndexByte(s, ':')
	if i == -1 {
		return "", 0, false, errors.New("not an ip:port")
	}

	ip = s[:i]
	portStr := s[i+1:]
	if len(ip) == 0 {
		return "", 0, false, errors.New("no IP")
	}
	if len(portStr) == 0 {
		return "", 0, false, errors.New("no port")
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, false, errors.New("invalid port " + strconv.Quote(portStr) + " parsing " + strconv.Quote(s))
	}
	port = uint16(port64)
	if ip[0] == '[' {
		if len(ip) < 2 || ip[len(ip)-1] != ']' {
			return "", 0, false, errors.New("missing ]")
		}
		ip = ip[1 : len(ip)-1]
		v6 = true
	}

	return ip, port, v6, nil
}
