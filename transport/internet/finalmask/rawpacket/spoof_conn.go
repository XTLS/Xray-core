package rawpacket

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type SpoofConn struct {
	sender    SpoofSender
	recver    SpoofReceiver
	relayIP   netip.Addr
	relayPort uint16

	recvBuf    []byte
	readClosed bool

	closeOnce sync.Once
}

func DialSpoof(relayAddr netip.AddrPort, spoofIPs []netip.Addr, srcPort uint16, ttl uint8, sendProto, recvProto string, peerSpoofIP netip.Addr) (net.Conn, error) {
	if sendProto == "" {
		sendProto = "tcp"
	}
	if recvProto == "" {
		recvProto = "udp"
	}

	if recvProto == "icmp" || recvProto == "icmpv6" {
		suppressICMPEchoReply()
	}

	sender, err := NewSender(sendProto, &SpoofSenderConfig{
		SourceIPs:  spoofIPs,
		SourcePort: srcPort,
		TTL:        ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("rawpacket: create sender: %w", err)
	}

	recver, err := NewReceiver(recvProto, &SpoofReceiverConfig{
		ListenPort:  srcPort,
		PeerSpoofIP: peerSpoofIP,
		BufferSize:  4 * 1024 * 1024,
	})
	if err != nil {
		sender.Close()
		return nil, fmt.Errorf("rawpacket: create receiver: %w", err)
	}

	return &SpoofConn{
		sender:    sender,
		recver:    recver,
		relayIP:   relayAddr.Addr(),
		relayPort: relayAddr.Port(),
		recvBuf:   make([]byte, 65536),
	}, nil
}

func (c *SpoofConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.sender.Send(b, c.relayIP, c.relayPort); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *SpoofConn) Read(buf []byte) (int, error) {
	data, _, _, err := c.recver.Receive()
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	n := copy(buf, data)
	return n, nil
}

func (c *SpoofConn) Close() error {
	c.sender.Close()
	c.recver.Close()
	return nil
}

func (c *SpoofConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *SpoofConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.relayIP.AsSlice(), Port: int(c.relayPort)}
}

func (c *SpoofConn) SetDeadline(t time.Time) error  { return nil }
func (c *SpoofConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *SpoofConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *SpoofConn) TcpMaskConn() {}
func (c *SpoofConn) RawConn() net.Conn { return nil }
func (c *SpoofConn) Splice() bool { return false }
