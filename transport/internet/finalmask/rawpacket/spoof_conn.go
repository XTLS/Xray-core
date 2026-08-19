package rawpacket

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// dialCounter round-robins the spoof source IP across connections so each
// session uses exactly one source address (per-session rotation instead of
// per-packet). This keeps the relay's (sessionID -> client address)
// mapping stable.
var dialCounter atomic.Uint64

type SpoofConn struct {
	sid     [8]byte
	crypto  *frameCrypto
	sender  SpoofSender
	tcp     *TCPSimState
	demux   *frameDemux
	recvCh  chan demuxData
	relayIP netip.Addr
	relayP  uint16

	maxPayload int

	writeMu sync.Mutex

	keepaliveStop chan struct{}
	closeOnce     sync.Once

	readDeadline  atomic.Int64 // unixNano, 0 = none
	writeDeadline atomic.Int64
}

func DialSpoof(relayAddr netip.AddrPort, spoofIPs []netip.Addr, srcPort uint16, ttl uint8, mtu uint32, sendProto, recvProto string, peerSpoofIP netip.Addr, psk []byte) (net.Conn, error) {
	if len(psk) == 0 {
		return nil, errors.New("rawpacket: auth (PSK) required in local mode")
	}
	if len(spoofIPs) == 0 {
		return nil, errors.New("rawpacket: at least one spoof IP required")
	}
	if sendProto == "" {
		sendProto = "tcp"
	}
	if recvProto == "" {
		recvProto = "udp"
	}

	if recvProto == "icmp" || recvProto == "icmpv6" {
		suppressICMPEchoReply()
	}

	sid, err := newSessionID()
	if err != nil {
		return nil, fmt.Errorf("rawpacket: session id: %w", err)
	}
	crypto, err := newFrameCrypto(psk, sid)
	if err != nil {
		return nil, fmt.Errorf("rawpacket: frame crypto: %w", err)
	}

	// One source IP per session: per-session rotation.
	srcIP := spoofIPs[dialCounter.Add(1)%uint64(len(spoofIPs))]
	sender, err := NewSender(sendProto, &SpoofSenderConfig{
		SourceIPs:  []netip.Addr{srcIP},
		SourcePort: srcPort,
		TTL:        ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("rawpacket: create sender: %w", err)
	}

	demux := getFrameDemux(recvProto, srcPort, peerSpoofIP)
	recvCh := make(chan demuxData, 64)
	if err := demux.register(sid, crypto, recvCh); err != nil {
		sender.Close()
		return nil, fmt.Errorf("rawpacket: create receiver: %w", err)
	}

	c := &SpoofConn{
		sid:           sid,
		crypto:        crypto,
		sender:        sender,
		tcp:           newTCPSimState(),
		demux:         demux,
		recvCh:        recvCh,
		relayIP:       relayAddr.Addr(),
		relayP:        relayAddr.Port(),
		maxPayload:    maxPayloadForMTU(mtu),
		keepaliveStop: make(chan struct{}),
	}
	go c.keepaliveLoop()
	return c, nil
}

// maxPayloadForMTU bounds the frame payload so the largest possible wire
// packet (IPv4 + TCP with options + frame overhead) stays within mtu.
func maxPayloadForMTU(mtu uint32) int {
	if mtu == 0 {
		return frameMaxPayload
	}
	p := int(mtu) - 20 - 40 - frameOverhead
	if p < 1 {
		p = 1
	}
	if p > frameMaxPayload {
		p = frameMaxPayload
	}
	return p
}

func (c *SpoofConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if dl := c.writeDeadline.Load(); dl != 0 {
		if time.Now().UnixNano() >= dl {
			return 0, os.ErrDeadlineExceeded
		}
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > c.maxPayload {
			chunk = chunk[:c.maxPayload]
		}
		frame, err := c.crypto.seal(false, chunk, false)
		if err != nil {
			return written, err
		}
		if err := c.sender.Send(frame, c.relayIP, c.relayP, c.tcp); err != nil {
			return written, err
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

func (c *SpoofConn) Read(buf []byte) (int, error) {
	dl := c.readDeadline.Load()
	if dl != 0 && time.Now().UnixNano() >= dl {
		return 0, os.ErrDeadlineExceeded
	}

	var timer *time.Timer
	var timeout <-chan time.Time
	if dl != 0 {
		timer = time.NewTimer(time.Until(time.Unix(0, dl)))
		timeout = timer.C
		defer timer.Stop()
	}

	select {
	case data, ok := <-c.recvCh:
		if !ok {
			return 0, errors.New("rawpacket: connection closed")
		}
		if data.tcp != nil && data.tcp.Flags != 0 {
			c.tcp.observePeer(data.tcp.Seq, len(data.payload))
		}
		return copy(buf, data.payload), nil
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

// keepaliveLoop keeps the relay session alive during idle periods so the
// relay's garbage collector does not reap an idle but healthy connection.
func (c *SpoofConn) keepaliveLoop() {
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.keepaliveStop:
			return
		case <-t.C:
			c.writeMu.Lock()
			frame, err := c.crypto.seal(false, nil, true)
			if err == nil {
				_ = c.sender.Send(frame, c.relayIP, c.relayP, c.tcp)
			}
			c.writeMu.Unlock()
		}
	}
}

func (c *SpoofConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.keepaliveStop)
		c.demux.unregister(c.sid)
		c.sender.Close()
	})
	return nil
}

func (c *SpoofConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (c *SpoofConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.relayIP.AsSlice(), Port: int(c.relayP)}
}

func setDeadline(d *atomic.Int64, t time.Time) error {
	if t.IsZero() {
		d.Store(0)
		return nil
	}
	d.Store(t.UnixNano())
	return nil
}

func (c *SpoofConn) SetDeadline(t time.Time) error {
	if err := setDeadline(&c.readDeadline, t); err != nil {
		return err
	}
	return setDeadline(&c.writeDeadline, t)
}

func (c *SpoofConn) SetReadDeadline(t time.Time) error {
	return setDeadline(&c.readDeadline, t)
}

func (c *SpoofConn) SetWriteDeadline(t time.Time) error {
	return setDeadline(&c.writeDeadline, t)
}

func (c *SpoofConn) TcpMaskConn()      {}
func (c *SpoofConn) RawConn() net.Conn { return nil }
func (c *SpoofConn) Splice() bool      { return false }
