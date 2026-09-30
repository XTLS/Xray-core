package wireguard

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func newICMPTestStack(t *testing.T) *netTun {
	t.Helper()
	dev, _, gstack, err := CreateNetTUN([]netip.Addr{
		netip.MustParseAddr("10.66.0.1"),
		netip.MustParseAddr("fd00::1"),
	}, nil, 1420, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	CreateForwarder(gstack, func(conn net.Conn, dest net.Destination) { conn.Close() })
	CreateICMPEchoResponder(gstack)
	return dev.(*netTun)
}

// startReader must run before the request is written: the stack may answer
// synchronously inside Write, and netTun hands packets over an unbuffered channel.
func startReader(dev *netTun) <-chan []byte {
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		sizes := make([]int, 1)
		if _, err := dev.Read([][]byte{buf}, sizes, 0); err == nil {
			got <- buf[:sizes[0]]
		}
	}()
	return got
}

func awaitPacket(t *testing.T, got <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-got:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("no echo reply from the stack")
		return nil
	}
}

func TestICMPv4EchoReply(t *testing.T) {
	dev := newICMPTestStack(t)
	src := tcpip.AddrFrom4([4]byte{10, 66, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	payload := []byte("xray wireguard ping")

	icmpMsg := make([]byte, header.ICMPv4MinimumSize+len(payload))
	req := header.ICMPv4(icmpMsg)
	req.SetType(header.ICMPv4Echo)
	req.SetIdent(0x1234)
	req.SetSequence(7)
	copy(req.Payload(), payload)
	req.SetChecksum(header.ICMPv4Checksum(req[:header.ICMPv4MinimumSize], checksum.Checksum(payload, 0)))

	pkt := make([]byte, header.IPv4MinimumSize+len(icmpMsg))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(pkt[header.IPv4MinimumSize:], icmpMsg)

	got := startReader(dev)
	if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
		t.Fatal(err)
	}

	reply := header.IPv4(awaitPacket(t, got))
	if !reply.IsValid(len(reply)) {
		t.Fatal("invalid ipv4 reply")
	}
	if reply.SourceAddress() != dst || reply.DestinationAddress() != src {
		t.Fatalf("reply addresses %v -> %v, want %v -> %v", reply.SourceAddress(), reply.DestinationAddress(), dst, src)
	}
	if reply.TransportProtocol() != header.ICMPv4ProtocolNumber {
		t.Fatalf("reply protocol %v, want icmpv4", reply.TransportProtocol())
	}
	echo := header.ICMPv4(reply.Payload())
	if echo.Type() != header.ICMPv4EchoReply {
		t.Fatalf("reply type %v, want echo reply", echo.Type())
	}
	if echo.Ident() != 0x1234 || echo.Sequence() != 7 {
		t.Fatalf("reply ident/seq %#x/%d, want 0x1234/7", echo.Ident(), echo.Sequence())
	}
	if !bytes.Equal(echo.Payload(), payload) {
		t.Fatalf("reply payload %q, want %q", echo.Payload(), payload)
	}
	if checksum.Checksum(echo, 0) != 0xffff {
		t.Fatal("bad icmpv4 checksum")
	}
}

func TestICMPv6EchoReply(t *testing.T) {
	dev := newICMPTestStack(t)
	src := tcpip.AddrFrom16([16]byte{0xfd, 15: 2})
	dst := tcpip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 15: 0x11})
	payload := []byte("xray wireguard ping6")

	icmpMsg := make([]byte, header.ICMPv6MinimumSize+len(payload))
	req := header.ICMPv6(icmpMsg)
	req.SetType(header.ICMPv6EchoRequest)
	req.SetIdent(0x4321)
	req.SetSequence(9)
	copy(req.Payload(), payload)
	req.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      req[:header.ICMPv6MinimumSize],
		Src:         src,
		Dst:         dst,
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	}))

	pkt := make([]byte, header.IPv6MinimumSize+len(icmpMsg))
	ip := header.IPv6(pkt)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(icmpMsg)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	copy(pkt[header.IPv6MinimumSize:], icmpMsg)

	got := startReader(dev)
	if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
		t.Fatal(err)
	}

	reply := header.IPv6(awaitPacket(t, got))
	if !reply.IsValid(len(reply)) {
		t.Fatal("invalid ipv6 reply")
	}
	if reply.SourceAddress() != dst || reply.DestinationAddress() != src {
		t.Fatalf("reply addresses %v -> %v, want %v -> %v", reply.SourceAddress(), reply.DestinationAddress(), dst, src)
	}
	echo := header.ICMPv6(reply.Payload())
	if echo.Type() != header.ICMPv6EchoReply {
		t.Fatalf("reply type %v, want echo reply", echo.Type())
	}
	if echo.Ident() != 0x4321 || echo.Sequence() != 9 {
		t.Fatalf("reply ident/seq %#x/%d, want 0x4321/9", echo.Ident(), echo.Sequence())
	}
	if !bytes.Equal(echo.Payload(), payload) {
		t.Fatalf("reply payload %q, want %q", echo.Payload(), payload)
	}
	zeroed := header.ICMPv6(append([]byte(nil), echo[:header.ICMPv6MinimumSize]...))
	zeroed.SetChecksum(0)
	want := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      zeroed,
		Src:         dst,
		Dst:         src,
		PayloadCsum: checksum.Checksum(echo.Payload(), 0),
		PayloadLen:  len(echo.Payload()),
	})
	if echo.Checksum() != want {
		t.Fatalf("icmpv6 checksum %#x, want %#x", echo.Checksum(), want)
	}
}
