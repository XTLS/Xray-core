//go:build windows && (amd64 || 386)

package rawpacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/transport/internet/finalmask/rawpacket/windivert"
	"golang.org/x/sys/windows"
)

const PlatformSupported = true

// closeGracePeriod caps how long Close() waits for the divert goroutine to
// observe the kernel-emitted real ClientHello and perform the reorder
// (fake → real). In practice this completes in microseconds; the cap
// bounds the pathological case where the kernel buffers the packet.
const closeGracePeriod = 2 * time.Second

// windowsSpoofer uses a single WinDivert handle for both capture and
// injection. Sequential Send() calls on one handle traverse one driver queue,
// so the fake provably precedes the released real on the wire — a guarantee
// two separate handles cannot make because cross-handle order depends on the
// scheduler.
type windowsSpoofer struct {
	method   Method
	src, dst netip.AddrPort
	divertH  *windivert.Handle
	ttl      uint8

	fakeReady chan []byte   // buffered(1): staged by Inject
	done      chan struct{} // closed by run() on exit
	closeOnce sync.Once
	runErr    atomic.Pointer[error]
}

func newRawSpoofer(conn net.Conn, method Method, ttl uint8) (rawSpoofer, error) {
	_, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	filter, err := windivert.BidirectionalTCP(src, dst)
	if err != nil {
		return nil, err
	}
	log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: opening WinDivert handle filter=%q src=%s dst=%s method=%s", filter, src, dst, method)})
	divertH, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		return nil, err
	}
	log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: WinDivert opened src=%s dst=%s method=%s", src, dst, method)})
	s := &windowsSpoofer{
		method:    method,
		src:       src,
		dst:       dst,
		divertH:   divertH,
		ttl:       ttl,
		fakeReady: make(chan []byte, 1),
		done:      make(chan struct{}),
	}
	go s.run()
	return s, nil
}

func (s *windowsSpoofer) Inject(payload []byte) error {
	log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: Inject called payload_len=%d", len(payload))})
	select {
	case s.fakeReady <- payload:
		log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: injected payload onto fakeReady"})
		return nil
	case <-s.done:
		if p := s.runErr.Load(); p != nil {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Inject failed spoofer closed err=%v", *p)})
			return *p
		}
		return errors.New("rawpacket: spoofer closed before Inject")
	}
}

func (s *windowsSpoofer) Close() error {
	s.closeOnce.Do(func() {
		// Give run() a grace window to finish handling the real packet.
		select {
		case <-s.done:
		case <-time.After(closeGracePeriod):
			// Force Recv() to return by closing the divert handle.
			s.divertH.Close()
			<-s.done
		}
	})
	if p := s.runErr.Load(); p != nil {
		return *p
	}
	return nil
}

func (s *windowsSpoofer) recordErr(err error) { s.runErr.Store(&err) }

func (s *windowsSpoofer) run() {
	defer close(s.done)
	defer s.divertH.Close()
	defer log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: run() exiting"})

	log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: run() started"})
	buf := make([]byte, windivert.MTUMax)
	packetCount := 0
	for {
		n, addr, err := s.divertH.Recv(buf)
		if err != nil {
			if errors.Is(err, windows.ERROR_OPERATION_ABORTED) ||
				errors.Is(err, windows.ERROR_NO_DATA) {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: Recv returned expected err=%v", err)})
				return
			}
			log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Recv err=%v", err)})
			s.recordErr(err)
			return
		}
		pkt := buf[:n]
		packetCount++
		seq, _, _, payloadLen, ok := parseTCPPacket(pkt, addr.IPv6())
		if !ok {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: pkt#%d not TCP/passthrough len=%d", packetCount, n)})
			_, sendErr := s.divertH.Send(pkt, &addr)
			if sendErr != nil {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Send err after parse fail=%v", sendErr)})
				s.recordErr(sendErr)
				return
			}
			continue
		}

		// Check direction. s.src is the local (client) address.
		var isOutbound bool
		if addr.IPv6() {
			if len(pkt) < IPv6MinimumSize+TCPMinimumSize {
				_, _ = s.divertH.Send(pkt, &addr)
				continue
			}
			ip6 := IPv6(pkt)
			srcIP := ip6.Src()
			srcPort := binary.BigEndian.Uint16(pkt[IPv6MinimumSize:])
			if srcIP == s.src.Addr() && srcPort == s.src.Port() {
				isOutbound = true
			} else if srcIP == s.dst.Addr() && srcPort == s.dst.Port() {
				isOutbound = false
			} else {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: pkt#%d direction-unknown (neither side) passthrough", packetCount)})
				_, _ = s.divertH.Send(pkt, &addr)
				continue
			}
		} else {
			if len(pkt) < IPv4MinimumSize+TCPMinimumSize {
				_, _ = s.divertH.Send(pkt, &addr)
				continue
			}
			ip4 := IPv4(pkt)
			srcIP := ip4.Src()
			srcPort := binary.BigEndian.Uint16(pkt[IPv4MinimumSize:])
			if srcIP == s.src.Addr() && srcPort == s.src.Port() {
				isOutbound = true
			} else if srcIP == s.dst.Addr() && srcPort == s.dst.Port() {
				isOutbound = false
			} else {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: pkt#%d direction-unknown (neither side) passthrough", packetCount)})
				_, _ = s.divertH.Send(pkt, &addr)
				continue
			}
		}

		if !isOutbound {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: pkt#%d inbound seq=%d payload=%d passthrough", packetCount, seq, payloadLen)})
			_, err := s.divertH.Send(pkt, &addr)
			if err != nil {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Send err inbound=%v", err)})
				s.recordErr(err)
				return
			}
			continue
		}

		if payloadLen == 0 {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: pkt#%d outbound ack/ctrl passthrough", packetCount)})
			_, err := s.divertH.Send(pkt, &addr)
			if err != nil {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Send err outbound-ctrl=%v", err)})
				s.recordErr(err)
				return
			}
			continue
		}

		// Outbound data packet — the real ClientHello.
		log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: pkt#%d outbound DATA seq=%d payload=%d", packetCount, seq, payloadLen)})
		var fake []byte
		select {
		case fake = <-s.fakeReady:
			log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: fakeReady consumed fake_len=%d", len(fake))})
		default:
			// Inject() not yet called — pass through and keep observing.
			log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: fakeReady empty, pass-through until Inject called"})
			_, err := s.divertH.Send(pkt, &addr)
			if err != nil {
				log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Send err data-passthrough=%v", err)})
				s.recordErr(err)
				return
			}
			continue
		}

		// Build the spoofed packet from the captured real packet template.
		// This preserves all TCP options and IP ID sequencing from the real
		// connection. synSeq is derived from the captured data seq (first
		// data after handshake always has seq = synSeq + 1).
		synSeq := seq - 1
		log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: fmt.Sprintf("rawpacket: building spoof seq=%d synSeq=%d fake=%d method=%s", seq, synSeq, len(fake), s.method)})
		frame, err := buildSpoofFromCapturedPacket(pkt, addr.IPv6(), synSeq, fake, s.method)
		if err != nil {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: buildSpoofFromCapturedPacket err=%v", err)})
			s.recordErr(err)
			return
		}
		fakeAddr := addr // inherit Outbound, IfIdx
		// buildSpoofFromCapturedPacket emits ready-to-wire bytes with
		// correct checksums. The driver would recompute checksums on Send
		// when TCPChecksum/IPChecksum are 0. Force both to 1 to preserve
		// intentional corruption (wrong-checksum method) and keep our bytes.
		fakeAddr.SetIPChecksum(true)
		fakeAddr.SetTCPChecksum(true)
		log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: sending fake frame"})
		_, err = s.divertH.Send(frame, &fakeAddr)
		if err != nil {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Send fake err=%v", err)})
			s.recordErr(err)
			return
		}
		log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: sending real frame"})
		_, err = s.divertH.Send(pkt, &addr)
		if err != nil {
			log.Record(&log.GeneralMessage{Severity: log.Severity_Error, Content: fmt.Sprintf("rawpacket: Send real err=%v", err)})
			s.recordErr(err)
			return
		}
		log.Record(&log.GeneralMessage{Severity: log.Severity_Debug, Content: "rawpacket: reorder complete"})
		return // single-shot reorder complete
	}
}

func parseTCPPacket(pkt []byte, isV6 bool) (seq, ack uint32, options []byte, payloadLen int, ok bool) {
	if isV6 {
		if len(pkt) < IPv6MinimumSize+TCPMinimumSize {
			return 0, 0, nil, 0, false
		}
		ip := IPv6(pkt)
		if ip.TransportProtocol() != TCPProtocolNumber {
			return 0, 0, nil, 0, false
		}
		tcp := TCP(pkt[IPv6MinimumSize:])
		tcpHdr := int(tcp.DataOffset())
		if tcpHdr < TCPMinimumSize || IPv6MinimumSize+tcpHdr > len(pkt) {
			return 0, 0, nil, 0, false
		}
		total := IPv6MinimumSize + int(ip.PayloadLength())
		if total == IPv6MinimumSize || total > len(pkt) {
			total = len(pkt)
		}
		if total < IPv6MinimumSize+tcpHdr {
			return 0, 0, nil, 0, false
		}
		return tcp.SequenceNumber(), tcp.AckNumber(), slices.Clone(tcp.Options()),
			total - IPv6MinimumSize - tcpHdr, true
	}
	if len(pkt) < IPv4MinimumSize+TCPMinimumSize {
		return 0, 0, nil, 0, false
	}
	ip := IPv4(pkt)
	if ip.Protocol() != TCPProtocolNumber {
		return 0, 0, nil, 0, false
	}
	ihl := int(ip.HeaderLength())
	// ihl+TCPMinimumSize guards the TCP-header field reads below; without
	// this, an IPv4 packet with options (ihl>20) against a 40-byte buffer
	// reads past the TCP slice when calling DataOffset.
	if ihl < IPv4MinimumSize || ihl+TCPMinimumSize > len(pkt) {
		return 0, 0, nil, 0, false
	}
	tcp := TCP(pkt[ihl:])
	tcpHdr := int(tcp.DataOffset())
	if tcpHdr < TCPMinimumSize || ihl+tcpHdr > len(pkt) {
		return 0, 0, nil, 0, false
	}
	total := int(ip.TotalLength())
	if total == 0 || total > len(pkt) {
		total = len(pkt)
	}
	if total < ihl+tcpHdr {
		return 0, 0, nil, 0, false
	}
	return tcp.SequenceNumber(), tcp.AckNumber(), slices.Clone(tcp.Options()),
		total - ihl - tcpHdr, true
}
