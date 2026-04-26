package icmp

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestParseEchoRequest(t *testing.T) {
	t.Run("ipv4 echo", func(t *testing.T) {
		var zero tcpip.Address
		packet := []byte{
			byte(header.ICMPv4Echo), 0,
			0, 0,
			0x12, 0x34,
			0x56, 0x78,
			0xaa, 0xbb,
		}
		if err := RewriteChecksum(header.IPv4ProtocolNumber, packet, zero, zero); err != nil {
			t.Fatal(err)
		}

		ident, sequence, ok := ParseEchoRequest(header.IPv4ProtocolNumber, packet)
		if !ok {
			t.Fatal("expected ipv4 echo request to parse")
		}
		if ident != 0x1234 || sequence != 0x5678 {
			t.Fatalf("unexpected ident/sequence: %x/%x", ident, sequence)
		}
	})

	t.Run("ipv6 echo", func(t *testing.T) {
		packet := []byte{
			byte(header.ICMPv6EchoRequest), 0,
			0, 0,
			0xab, 0xcd,
			0xef, 0x01,
			0xaa, 0xbb,
		}
		src := tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		dst := tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		if err := RewriteChecksum(header.IPv6ProtocolNumber, packet, src, dst); err != nil {
			t.Fatal(err)
		}

		ident, sequence, ok := ParseEchoRequest(header.IPv6ProtocolNumber, packet)
		if !ok {
			t.Fatal("expected ipv6 echo request to parse")
		}
		if ident != 0xabcd || sequence != 0xef01 {
			t.Fatalf("unexpected ident/sequence: %x/%x", ident, sequence)
		}
	})
}

func TestRewriteChecksum(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		var zero tcpip.Address
		packet := []byte{
			byte(header.ICMPv4Echo), 0,
			0xff, 0xff,
			0x12, 0x34,
			0x56, 0x78,
			0xaa, 0xbb, 0xcc,
		}
		if err := RewriteChecksum(header.IPv4ProtocolNumber, packet, zero, zero); err != nil {
			t.Fatal(err)
		}

		icmpHdr := header.ICMPv4(packet)
		if got, want := icmpHdr.Checksum(), header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksumPayloadV4(icmpHdr.Payload())); got != want {
			t.Fatalf("unexpected ipv4 checksum: got %x want %x", got, want)
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		packet := []byte{
			byte(header.ICMPv6EchoReply), 0,
			0xff, 0xff,
			0x12, 0x34,
			0x56, 0x78,
			0xaa, 0xbb, 0xcc,
		}
		src := tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		dst := tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		if err := RewriteChecksum(header.IPv6ProtocolNumber, packet, src, dst); err != nil {
			t.Fatal(err)
		}

		icmpHdr := header.ICMPv6(packet)
		want := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr[:header.ICMPv6MinimumSize],
			Src:         src,
			Dst:         dst,
			PayloadLen:  len(icmpHdr.Payload()),
			PayloadCsum: checksumPayloadV6(icmpHdr.Payload()),
		})
		if got := icmpHdr.Checksum(); got != want {
			t.Fatalf("unexpected ipv6 checksum: got %x want %x", got, want)
		}
	})
}

func TestBuildLocalEchoReply(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		request := []byte{
			byte(header.ICMPv4Echo), 0,
			0, 0,
			0x12, 0x34,
			0x56, 0x78,
			0xaa, 0xbb, 0xcc,
		}
		src := tcpip.Address{}
		dst := tcpip.Address{}
		if err := RewriteChecksum(header.IPv4ProtocolNumber, request, src, dst); err != nil {
			t.Fatal(err)
		}

		reply, err := BuildLocalEchoReply(header.IPv4ProtocolNumber, request, dst, src)
		if err != nil {
			t.Fatal(err)
		}
		if request[0] != byte(header.ICMPv4Echo) {
			t.Fatal("request mutated")
		}
		icmpHdr := header.ICMPv4(reply)
		if icmpHdr.Type() != header.ICMPv4EchoReply || icmpHdr.Code() != header.ICMPv4UnusedCode {
			t.Fatalf("unexpected ipv4 reply type/code: %d/%d", icmpHdr.Type(), icmpHdr.Code())
		}
		if icmpHdr.Ident() != 0x1234 || icmpHdr.Sequence() != 0x5678 {
			t.Fatalf("unexpected ipv4 ident/sequence: %x/%x", icmpHdr.Ident(), icmpHdr.Sequence())
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		request := []byte{
			byte(header.ICMPv6EchoRequest), 0,
			0, 0,
			0xab, 0xcd,
			0xef, 0x01,
			0xaa, 0xbb, 0xcc,
		}
		src := tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		dst := tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		if err := RewriteChecksum(header.IPv6ProtocolNumber, request, src, dst); err != nil {
			t.Fatal(err)
		}

		reply, err := BuildLocalEchoReply(header.IPv6ProtocolNumber, request, dst, src)
		if err != nil {
			t.Fatal(err)
		}
		if request[0] != byte(header.ICMPv6EchoRequest) {
			t.Fatal("request mutated")
		}
		icmpHdr := header.ICMPv6(reply)
		if icmpHdr.Type() != header.ICMPv6EchoReply || icmpHdr.Code() != header.ICMPv6UnusedCode {
			t.Fatalf("unexpected ipv6 reply type/code: %d/%d", icmpHdr.Type(), icmpHdr.Code())
		}
		if icmpHdr.Ident() != 0xabcd || icmpHdr.Sequence() != 0xef01 {
			t.Fatalf("unexpected ipv6 ident/sequence: %x/%x", icmpHdr.Ident(), icmpHdr.Sequence())
		}
	})
}

func checksumPayloadV4(payload []byte) uint16 {
	return checksum.Checksum(payload, 0)
}

func checksumPayloadV6(payload []byte) uint16 {
	return checksum.Checksum(payload, 0)
}
