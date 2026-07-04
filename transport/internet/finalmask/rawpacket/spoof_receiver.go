package rawpacket

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

type rawRecvSocket struct {
	fd     int
	buf    []byte
	closed bool
	proto  uint8
}

func newRawRecvSocket(domain, proto int, bufSize int) (*rawRecvSocket, error) {
	fd, err := unix.Socket(domain, unix.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("rawpacket: socket: %w", err)
	}
	if bufSize > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize)
	}
	// 1-second timeout for clean shutdown
	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return &rawRecvSocket{fd: fd, buf: make([]byte, 65536)}, nil
}

func (r *rawRecvSocket) recv() ([]byte, bool) {
	n, _, err := unix.Recvfrom(r.fd, r.buf, 0)
	if err != nil {
		return nil, false
	}
	if n == 0 {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	return out, true
}

func (r *rawRecvSocket) close() {
	if !r.closed {
		r.closed = true
		unix.Close(r.fd)
	}
}

type tcpReceiver struct {
	raw *rawRecvSocket
	cfg *SpoofReceiverConfig
}

func newTCPReceiver(cfg *SpoofReceiverConfig) (*tcpReceiver, error) {
	raw, err := newRawRecvSocket(unix.AF_INET, unix.IPPROTO_TCP, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &tcpReceiver{raw: raw, cfg: cfg}, nil
}

func (r *tcpReceiver) Receive() ([]byte, netip.Addr, uint16, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			continue
		}
		_, flags, payload, srcIP, _, srcPort, dstPort, ok := ParseRawTCPPacket(pkt)
		if !ok || dstPort != r.cfg.ListenPort || flags&TCPFlagSyn == 0 {
			continue
		}
		if r.cfg.PeerSpoofIP.IsValid() && srcIP != r.cfg.PeerSpoofIP {
			continue
		}
		return payload, srcIP, srcPort, nil
	}
}

func (r *tcpReceiver) Close() error {
	r.raw.close()
	return nil
}

type udpReceiver struct {
	raw *rawRecvSocket
	cfg *SpoofReceiverConfig
}

func newUDPReceiver(cfg *SpoofReceiverConfig) (*udpReceiver, error) {
	raw, err := newRawRecvSocket(unix.AF_INET, unix.IPPROTO_UDP, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &udpReceiver{raw: raw, cfg: cfg}, nil
}

func (r *udpReceiver) Receive() ([]byte, netip.Addr, uint16, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			continue
		}
		payload, srcPort, dstPort, ok := ParseUDPPacket(pkt)
		if !ok || dstPort != r.cfg.ListenPort {
			continue
		}
		srcIP, _, _ := ParseSrcIP(pkt, false)
		if r.cfg.PeerSpoofIP.IsValid() && srcIP != r.cfg.PeerSpoofIP {
			continue
		}
		return payload, srcIP, srcPort, nil
	}
}

func (r *udpReceiver) Close() error {
	r.raw.close()
	return nil
}

type icmpReceiver struct {
	raw *rawRecvSocket
	cfg *SpoofReceiverConfig
}

func newICMPReceiver(cfg *SpoofReceiverConfig) (*icmpReceiver, error) {
	raw, err := newRawRecvSocket(unix.AF_INET, unix.IPPROTO_ICMP, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &icmpReceiver{raw: raw, cfg: cfg}, nil
}

func (r *icmpReceiver) Receive() ([]byte, netip.Addr, uint16, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			continue
		}
		id, _, payload, ok := ParseICMPv4Echo(pkt)
		if !ok {
			continue
		}
		srcIP, _, _ := ParseSrcIP(pkt, false)
		if r.cfg.PeerSpoofIP.IsValid() && srcIP != r.cfg.PeerSpoofIP {
			continue
		}
		return payload, srcIP, id, nil
	}
}

func (r *icmpReceiver) Close() error {
	r.raw.close()
	return nil
}

type icmpv6Receiver struct {
	raw *rawRecvSocket
	cfg *SpoofReceiverConfig
}

func newICMPv6Receiver(cfg *SpoofReceiverConfig) (*icmpv6Receiver, error) {
	// Non-standard: protocol 58 on IPv4 (same as reference)
	raw, err := newRawRecvSocket(unix.AF_INET, int(ProtocolICMPv6), cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &icmpv6Receiver{raw: raw, cfg: cfg}, nil
}

func (r *icmpv6Receiver) Receive() ([]byte, netip.Addr, uint16, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			continue
		}
		id, _, payload, ok := ParseICMPv6Echo(pkt)
		if !ok {
			continue
		}
		srcIP, _, _ := ParseSrcIP(pkt, false)
		if r.cfg.PeerSpoofIP.IsValid() && srcIP != r.cfg.PeerSpoofIP {
			continue
		}
		return payload, srcIP, id, nil
	}
}

func (r *icmpv6Receiver) Close() error {
	r.raw.close()
	return nil
}
