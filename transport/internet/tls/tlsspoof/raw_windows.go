//go:build windows && (amd64 || 386)

package tlsspoof

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/transport/internet/tls/tlsspoof/windivert"
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

	fakeReady chan []byte   // buffered(1): staged by Inject
	done      chan struct{} // closed by run() on exit
	closeOnce sync.Once
	runErr    atomic.Pointer[error]
}

func newRawSpoofer(conn net.Conn, method Method) (rawSpoofer, error) {
	_, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	filter, err := windivert.OutboundTCP(src, dst)
	if err != nil {
		return nil, err
	}
	divertH, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		return nil, err
	}
	s := &windowsSpoofer{
		method:    method,
		src:       src,
		dst:       dst,
		divertH:   divertH,
		fakeReady: make(chan []byte, 1),
		done:      make(chan struct{}),
	}
	go s.run()
	return s, nil
}

func (s *windowsSpoofer) Inject(payload []byte) error {
	select {
	case s.fakeReady <- payload:
		return nil
	case <-s.done:
		if p := s.runErr.Load(); p != nil {
			return *p
		}
		return errors.New("tls_spoof: spoofer closed before Inject")
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

	buf := make([]byte, windivert.MTUMax)
	for {
		n, addr, err := s.divertH.Recv(buf)
		if err != nil {
			if errors.Is(err, windows.ERROR_OPERATION_ABORTED) ||
				errors.Is(err, windows.ERROR_NO_DATA) {
				return
			}
			s.recordErr(err)
			return
		}
		pkt := buf[:n]
		seq, ack, tcpOptions, payloadLen, ok := parseTCPPacket(pkt, addr.IPv6())
		if !ok {
			// Our filter is OutboundTCP(src, dst); a non-TCP or truncated
			// match means driver state is suspect. Re-inject so the kernel
			// still sees the byte stream, then abort — continuing would risk
			// reordering against an unknown reference point.
			_, sendErr := s.divertH.Send(pkt, &addr)
			if sendErr != nil {
				s.recordErr(sendErr)
				return
			}
			s.recordErr(errors.New("windivert received malformed packet matching spoof filter"))
			return
		}
		if payloadLen == 0 {
			// Handshake ACK, keepalive, FIN — pass through unchanged.
			_, err := s.divertH.Send(pkt, &addr)
			if err != nil {
				s.recordErr(err)
				return
			}
			continue
		}

		// Non-empty outbound TCP payload = the real ClientHello.
		var fake []byte
		select {
		case fake = <-s.fakeReady:
		default:
			// Inject() not yet called — pass through and keep observing.
			_, err := s.divertH.Send(pkt, &addr)
			if err != nil {
				s.recordErr(err)
				return
			}
			continue
		}

		var timestamp uint32
		if tsVal, hasTS := ParseTCPOptions(tcpOptions); hasTS {
			timestamp = tsVal
		}
		frame, err := buildSpoofFrame(s.method, s.src, s.dst, seq, ack, timestamp, tcpOptions, fake)
		if err != nil {
			s.recordErr(err)
			return
		}
		fakeAddr := addr // inherit Outbound, IfIdx
		// buildSpoofFrame emits ready-to-wire bytes. The driver recomputes
		// checksums on Send when TCPChecksum/IPChecksum are 0 — which would
		// overwrite the intentionally corrupt checksum in WrongChecksum mode.
		// Force both to 1 to keep our bytes intact.
		fakeAddr.SetIPChecksum(true)
		fakeAddr.SetTCPChecksum(true)
		_, err = s.divertH.Send(frame, &fakeAddr)
		if err != nil {
			s.recordErr(err)
			return
		}
		_, err = s.divertH.Send(pkt, &addr)
		if err != nil {
			s.recordErr(err)
			return
		}
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
