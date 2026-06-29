package tun

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDNSHijacker_HijackMode(t *testing.T) {
	hijacker := NewDNSHijacker(DNSHijackOptions{
		Mode:             "hijack",
		DNSAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		LoopbackAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		TUNAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		Writer:           func(pkt []byte) error { return nil },
	})

	src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 12345)
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 53)
	pkt := buildUDPPacket(src, dst)
	consumed, _ := hijacker.Process(pkt)
	if !consumed {
		t.Fatal("hijack mode should consume loopback DNS query")
	}
}

func TestDNSHijacker_NativeMode(t *testing.T) {
	hijacker := NewDNSHijacker(DNSHijackOptions{
		Mode:             "native",
		DNSAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		LoopbackAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		TUNAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		Writer:           func(pkt []byte) error { return nil },
	})

	src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 12345)
	dst := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 53)
	pkt := buildUDPPacket(src, dst)
	consumed, _ := hijacker.Process(pkt)
	if consumed {
		t.Fatal("native mode should not consume DNS")
	}
}

func TestDNSHijacker_DisabledMode(t *testing.T) {
	hijacker := NewDNSHijacker(DNSHijackOptions{
		Mode:             "disabled",
		DNSAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		LoopbackAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		TUNAddresses:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		Writer:           func(pkt []byte) error { return nil },
	})

	src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 12345)
	dst := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 53)
	pkt := buildUDPPacket(src, dst)
	consumed, _ := hijacker.Process(pkt)
	if consumed {
		t.Fatal("disabled mode should not consume DNS")
	}
}

func TestDNSHijacker_HijackModeIPv6(t *testing.T) {
	hijacker := NewDNSHijacker(DNSHijackOptions{
		Mode:             "hijack",
		DNSAddresses:     []netip.Addr{netip.MustParseAddr("fd00::1")},
		LoopbackAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		TUNAddresses:     []netip.Addr{netip.MustParseAddr("fd00::1")},
		Writer:           func(pkt []byte) error { return nil },
	})

	src := netip.AddrPortFrom(netip.MustParseAddr("fd00::2"), 12345)
	dst := netip.AddrPortFrom(netip.MustParseAddr("::1"), 53)
	pkt := buildUDPPacket(src, dst)
	consumed, _ := hijacker.Process(pkt)
	if !consumed {
		t.Fatal("hijack mode should consume IPv6 loopback DNS query")
	}
}

func buildUDPPacket(src, dst netip.AddrPort) []byte {
	if src.Addr().Is4() || src.Addr().Is4In6() {
		payload := []byte{0x00}
		udpLen := 8 + len(payload)
		totalLen := 20 + udpLen

		pkt := make([]byte, totalLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
		pkt[8] = 64
		pkt[9] = 17

		src4 := src.Addr().As4()
		dst4 := dst.Addr().As4()
		copy(pkt[12:16], src4[:])
		copy(pkt[16:20], dst4[:])

		binary.BigEndian.PutUint16(pkt[20:22], src.Port())
		binary.BigEndian.PutUint16(pkt[22:24], dst.Port())
		binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

		copy(pkt[28:], payload)
		return pkt
	}

	payload := []byte{0x00}
	udpLen := 8 + len(payload)
	totalLen := 40 + udpLen

	pkt := make([]byte, totalLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17
	pkt[7] = 64

	src16 := src.Addr().As16()
	dst16 := dst.Addr().As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])

	binary.BigEndian.PutUint16(pkt[40:42], src.Port())
	binary.BigEndian.PutUint16(pkt[42:44], dst.Port())
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))

	copy(pkt[48:], payload)
	return pkt
}
