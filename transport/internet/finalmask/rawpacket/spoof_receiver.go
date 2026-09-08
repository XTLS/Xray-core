package rawpacket

import (
	"errors"
	"net/netip"
)

var errReceiverClosed = errors.New("rawpacket: receiver closed")

// rawPktRecv is the platform-specific raw socket: unix SOCK_RAW on
// darwin/freebsd/linux, WinDivert on windows (amd64/386).
type rawPktRecv interface {
	// recv returns a copy of one raw IP packet. ok is false when the
	// socket is closed or a transient read failure occurred (callers
	// must tolerate spurious false returns and re-try).
	recv() (pkt []byte, ok bool)
	// closed reports whether the socket has been closed (recv will no
	// longer produce packets and errReceiverClosed is the permanent
	// outcome).
	closed() bool
	close()
}

type tcpReceiver struct {
	raw rawPktRecv
	cfg *SpoofReceiverConfig
}

func newTCPReceiver(cfg *SpoofReceiverConfig) (*tcpReceiver, error) {
	raw, err := newRawRecvSocket(ProtocolTCP, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &tcpReceiver{raw: raw, cfg: cfg}, nil
}

func (r *tcpReceiver) Receive() ([]byte, netip.Addr, uint16, *TCPMeta, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			if r.raw.closed() {
				return nil, netip.Addr{}, 0, nil, errReceiverClosed
			}
			continue
		}
		seq, flags, payload, srcIP, dstIP, srcPort, dstPort, ok := ParseRawTCPPacket(pkt)
		if !ok || dstPort != r.cfg.ListenPort {
			continue
		}
		if r.cfg.PeerSpoofIP.IsValid() && srcIP != r.cfg.PeerSpoofIP {
			continue
		}
		return payload, srcIP, srcPort, &TCPMeta{Seq: seq, Flags: flags, DstIP: dstIP, DstPort: dstPort}, nil
	}
}

func (r *tcpReceiver) Close() error {
	r.raw.close()
	return nil
}

type udpReceiver struct {
	raw rawPktRecv
	cfg *SpoofReceiverConfig
}

func newUDPReceiver(cfg *SpoofReceiverConfig) (*udpReceiver, error) {
	raw, err := newRawRecvSocket(ProtocolUDP, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &udpReceiver{raw: raw, cfg: cfg}, nil
}

func (r *udpReceiver) Receive() ([]byte, netip.Addr, uint16, *TCPMeta, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			if r.raw.closed() {
				return nil, netip.Addr{}, 0, nil, errReceiverClosed
			}
			continue
		}
		payload, srcPort, dstPort, ok := ParseUDPPacket(pkt)
		if !ok || dstPort != r.cfg.ListenPort {
			continue
		}
		srcIP, dstIP, _ := ParseSrcIP(pkt, false)
		if r.cfg.PeerSpoofIP.IsValid() && srcIP != r.cfg.PeerSpoofIP {
			continue
		}
		return payload, srcIP, srcPort, &TCPMeta{DstIP: dstIP, DstPort: dstPort}, nil
	}
}

func (r *udpReceiver) Close() error {
	r.raw.close()
	return nil
}

type icmpReceiver struct {
	raw rawPktRecv
	cfg *SpoofReceiverConfig
}

func newICMPReceiver(cfg *SpoofReceiverConfig) (*icmpReceiver, error) {
	raw, err := newRawRecvSocket(ProtocolICMP, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &icmpReceiver{raw: raw, cfg: cfg}, nil
}

func (r *icmpReceiver) Receive() ([]byte, netip.Addr, uint16, *TCPMeta, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			if r.raw.closed() {
				return nil, netip.Addr{}, 0, nil, errReceiverClosed
			}
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
		return payload, srcIP, id, nil, nil
	}
}

func (r *icmpReceiver) Close() error {
	r.raw.close()
	return nil
}

type icmpv6Receiver struct {
	raw rawPktRecv
	cfg *SpoofReceiverConfig
}

func newICMPv6Receiver(cfg *SpoofReceiverConfig) (*icmpv6Receiver, error) {
	// Non-standard: protocol 58 on IPv4 (same as reference)
	raw, err := newRawRecvSocket(ProtocolICMPv6, cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	return &icmpv6Receiver{raw: raw, cfg: cfg}, nil
}

func (r *icmpv6Receiver) Receive() ([]byte, netip.Addr, uint16, *TCPMeta, error) {
	for {
		pkt, ok := r.raw.recv()
		if !ok {
			if r.raw.closed() {
				return nil, netip.Addr{}, 0, nil, errReceiverClosed
			}
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
		return payload, srcIP, id, nil, nil
	}
}

func (r *icmpv6Receiver) Close() error {
	r.raw.close()
	return nil
}
