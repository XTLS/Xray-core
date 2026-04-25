package tun

import (
	stdnet "net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestParseICMPEchoRequest(t *testing.T) {
	t.Run("ipv4 echo", func(t *testing.T) {
		var zero tcpip.Address
		packet := []byte{
			byte(header.ICMPv4Echo), 0,
			0, 0,
			0x12, 0x34,
			0x56, 0x78,
			0xaa, 0xbb,
		}
		if err := rewriteICMPChecksum(header.IPv4ProtocolNumber, packet, zero, zero); err != nil {
			t.Fatal(err)
		}

		ident, sequence, ok := parseICMPEchoRequest(header.IPv4ProtocolNumber, packet)
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
		if err := rewriteICMPChecksum(header.IPv6ProtocolNumber, packet, src, dst); err != nil {
			t.Fatal(err)
		}

		ident, sequence, ok := parseICMPEchoRequest(header.IPv6ProtocolNumber, packet)
		if !ok {
			t.Fatal("expected ipv6 echo request to parse")
		}
		if ident != 0xabcd || sequence != 0xef01 {
			t.Fatalf("unexpected ident/sequence: %x/%x", ident, sequence)
		}
	})
}

func TestIsMatchingICMPEchoReply(t *testing.T) {
	ipv4Reply := []byte{
		byte(header.ICMPv4EchoReply), 0,
		0, 0,
		0x12, 0x34,
		0x56, 0x78,
	}
	if err := rewriteICMPChecksum(header.IPv4ProtocolNumber, ipv4Reply, tcpip.Address{}, tcpip.Address{}); err != nil {
		t.Fatal(err)
	}
	if !isMatchingICMPEchoReply(header.IPv4ProtocolNumber, ipv4Reply, 0x1234, 0x5678) {
		t.Fatal("expected ipv4 echo reply to match")
	}
	if isMatchingICMPEchoReply(header.IPv4ProtocolNumber, ipv4Reply, 0x1234, 0x5679) {
		t.Fatal("unexpected ipv4 echo reply match")
	}
}

func TestNormalizeICMPEchoReply(t *testing.T) {
	t.Run("ipv4 raw socket payload with ip header", func(t *testing.T) {
		reply := []byte{
			0x45, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x01, 0x00, 0x00,
			127, 0, 0, 1,
			8, 8, 8, 8,
			byte(header.ICMPv4EchoReply), 0,
			0, 0,
			0x12, 0x34,
			0x56, 0x78,
		}

		normalized, err := normalizeICMPEchoReply(header.IPv4ProtocolNumber, reply)
		if err != nil {
			t.Fatal(err)
		}
		if len(normalized) != header.ICMPv4MinimumSize {
			t.Fatalf("unexpected normalized length: %d", len(normalized))
		}
		if !isMatchingICMPEchoReply(header.IPv4ProtocolNumber, normalized, 0x1234, 0x5678) {
			t.Fatal("expected normalized ipv4 echo reply to match")
		}
	})
}

func TestRewriteICMPChecksum(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		var zero tcpip.Address
		packet := []byte{
			byte(header.ICMPv4Echo), 0,
			0xff, 0xff,
			0x12, 0x34,
			0x56, 0x78,
			0xaa, 0xbb, 0xcc,
		}
		if err := rewriteICMPChecksum(header.IPv4ProtocolNumber, packet, zero, zero); err != nil {
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
		if err := rewriteICMPChecksum(header.IPv6ProtocolNumber, packet, src, dst); err != nil {
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

func TestICMPReplyAddrMatches(t *testing.T) {
	tests := []struct {
		name     string
		addr     stdnet.Addr
		expected stdnet.Addr
		match    bool
	}{
		{
			name:     "same udp addr",
			addr:     &stdnet.UDPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			expected: &stdnet.UDPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			match:    true,
		},
		{
			name:     "ip addr matches udp addr",
			addr:     &stdnet.IPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			expected: &stdnet.UDPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			match:    true,
		},
		{
			name:     "udp addr matches ip addr",
			addr:     &stdnet.UDPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			expected: &stdnet.IPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			match:    true,
		},
		{
			name:     "different ip",
			addr:     &stdnet.IPAddr{IP: stdnet.IPv4(1, 1, 1, 1)},
			expected: &stdnet.UDPAddr{IP: stdnet.IPv4(8, 8, 8, 8)},
			match:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := icmpReplyAddrMatches(tt.addr, tt.expected); got != tt.match {
				t.Fatalf("icmpReplyAddrMatches() = %v, want %v", got, tt.match)
			}
		})
	}
}

func TestDatagramICMPEchoIdentifier(t *testing.T) {
	ident, ok := datagramICMPEchoIdentifier(&stdnet.UDPAddr{IP: stdnet.IPv4zero, Port: 1234})
	if !ok {
		t.Fatal("expected UDP addr to produce a datagram icmp identifier")
	}
	if ident != 1234 {
		t.Fatalf("unexpected identifier: %d", ident)
	}

	if _, ok := datagramICMPEchoIdentifier(&stdnet.IPAddr{IP: stdnet.IPv4zero}); ok {
		t.Fatal("expected non-UDP addr to be rejected")
	}
}

func TestMatchICMPEchoReply(t *testing.T) {
	packet := []byte{
		byte(header.ICMPv4EchoReply), 0,
		0, 0,
		0x12, 0x34,
		0x56, 0x78,
	}
	if err := rewriteICMPChecksum(header.IPv4ProtocolNumber, packet, tcpip.Address{}, tcpip.Address{}); err != nil {
		t.Fatal(err)
	}

	if matchedIdent, ok := matchICMPEchoReply(header.IPv4ProtocolNumber, packet, 0x1234, 0x5678, 0, false); !ok || matchedIdent != 0x1234 {
		t.Fatalf("expected original identifier match, got ok=%v ident=%x", ok, matchedIdent)
	}
	if matchedIdent, ok := matchICMPEchoReply(header.IPv4ProtocolNumber, packet, 0xabcd, 0x5678, 0x1234, true); !ok || matchedIdent != 0x1234 {
		t.Fatalf("expected alternate identifier match, got ok=%v ident=%x", ok, matchedIdent)
	}
	if _, ok := matchICMPEchoReply(header.IPv4ProtocolNumber, packet, 0xabcd, 0x5678, 0, false); ok {
		t.Fatal("expected mismatched identifier to be rejected without alternate identifier")
	}
}

func TestRewriteICMPEchoIdentifier(t *testing.T) {
	packet := []byte{
		byte(header.ICMPv4EchoReply), 0,
		0, 0,
		0x12, 0x34,
		0x56, 0x78,
	}
	if err := rewriteICMPEchoIdentifier(header.IPv4ProtocolNumber, packet, 0xabcd); err != nil {
		t.Fatal(err)
	}
	if !isMatchingICMPEchoReply(header.IPv4ProtocolNumber, packet, 0xabcd, 0x5678) {
		t.Fatal("expected rewritten identifier to match")
	}
}

func checksumPayloadV4(payload []byte) uint16 {
	return checksum.Checksum(payload, 0)
}

func checksumPayloadV6(payload []byte) uint16 {
	return checksum.Checksum(payload, 0)
}
