package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/xtls/xray-core/common/net"
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

// receivedPacket represents a packet received from a peer connection
type receivedPacket struct {
	data     []byte
	endpoint conn.Endpoint
	err      error
}

// reduce duplicated code
type netBind struct {
	dns       dns.Client
	dnsOption dns.IPOption

	workers      int
	readQueue    chan *netReadInfo
	packetQueue  chan *receivedPacket
	startedMutex sync.Mutex
	started      bool
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
	bind.packetQueue = make(chan *receivedPacket, 100)

	// Start a dispatcher goroutine that matches readQueue requests with received packets
	bind.startedMutex.Lock()
	if !bind.started {
		bind.started = true
		go func() {
			for {
				packet, ok := <-bind.packetQueue
				if !ok {
					return
				}
				
				// Wait for a read request from WireGuard
				request, ok := <-bind.readQueue
				if !ok {
					return
				}
				
				// Copy packet data to the request buffer
				n := copy(request.buff, packet.data)
				request.bytes = n
				request.endpoint = packet.endpoint
				request.err = packet.err
				request.waiter.Done()
			}
		}()
	}
	bind.startedMutex.Unlock()

	fun := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		defer func() {
			if r := recover(); r != nil {
				n = 0
				err = errors.New("channel closed")
			}
		}()

		r := &netReadInfo{
			buff: bufs[0],
		}
		r.waiter.Add(1)
		bind.readQueue <- r
		r.waiter.Wait() // wait read goroutine done, or we will miss the result
		sizes[0], eps[0] = r.bytes, r.endpoint
		return 1, r.err
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
	if bind.packetQueue != nil {
		close(bind.packetQueue)
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

	// Start a goroutine that continuously reads from this connection
	// and sends received packets to the packet queue
	go func(conn net.Conn, endpoint *netEndpoint) {
		const maxPacketSize = 1500
		for {
			buf := make([]byte, maxPacketSize)
			n, err := conn.Read(buf)
			
			// Only process data if we successfully read something
			if err == nil && n > 3 {
				// Clear reserved bytes
				buf[1] = 0
				buf[2] = 0
				buf[3] = 0
			}
			
			packet := &receivedPacket{
				data:     buf[:n],
				endpoint: endpoint,
				err:      err,
			}
			
			// Try to send packet to queue; if queue is full or closed, exit
			select {
			case bind.packetQueue <- packet:
				// Packet sent successfully
			default:
				// Queue is full or closed, exit goroutine
				endpoint.conn = nil
				return
			}
			
			if err != nil {
				endpoint.conn = nil
				return
			}
		}
	}(c, endpoint)

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
