package tun

import (
	"net/netip"
	"testing"
)

func TestBuildICMPv4Unreachable(t *testing.T) {
	origSrc := netip.AddrFrom4([4]byte{10, 0, 0, 2})
	origDst := netip.AddrFrom4([4]byte{8, 8, 8, 8})

	origPayload := make([]byte, 28)
	origPayload[0] = 0x45
	origPayload[2] = 0x00
	origPayload[3] = 28
	origPayload[8] = 64
	origPayload[9] = 17
	src4 := origSrc.As4()
	dst4 := origDst.As4()
	copy(origPayload[12:16], src4[:])
	copy(origPayload[16:20], dst4[:])
	origPayload[20] = 0x30
	origPayload[21] = 0x39
	origPayload[22] = 0x00
	origPayload[23] = 0x35
	origPayload[24] = 0x00
	origPayload[25] = 0x08

	pkt := BuildICMPv4Unreachable(origSrc, origDst, origPayload)
	if len(pkt) < 28 {
		t.Fatal("packet too short, got", len(pkt))
	}
	if pkt[12] != 8 || pkt[13] != 8 || pkt[14] != 8 || pkt[15] != 8 {
		t.Fatal("src IP should be original dst")
	}
	if pkt[16] != 10 || pkt[17] != 0 || pkt[18] != 0 || pkt[19] != 2 {
		t.Fatal("dst IP should be original src")
	}
	if pkt[20] != 3 {
		t.Fatal("ICMP type should be 3, got", pkt[20])
	}
	if pkt[21] != 3 {
		t.Fatal("ICMP code should be 3, got", pkt[21])
	}
}

func TestBuildICMPv6Unreachable(t *testing.T) {
	origSrc := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	origDst := netip.AddrFrom16([16]byte{0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	origPayload := make([]byte, 48)
	origPayload[0] = 0x60
	src16 := origSrc.As16()
	dst16 := origDst.As16()
	copy(origPayload[8:24], src16[:])
	copy(origPayload[24:40], dst16[:])
	origPayload[40] = 0x30
	origPayload[41] = 0x39
	origPayload[42] = 0x00
	origPayload[43] = 0x35

	pkt := BuildICMPv6Unreachable(origSrc, origDst, origPayload)
	if len(pkt) < 48 {
		t.Fatal("packet too short, got", len(pkt))
	}
	if pkt[40] != 1 {
		t.Fatal("ICMPv6 type should be 1, got", pkt[40])
	}
	if pkt[41] != 4 {
		t.Fatal("ICMPv6 code should be 4, got", pkt[41])
	}
}

func validateChecksum(t *testing.T, data []byte) {
	t.Helper()
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		var val uint32
		if i+1 < len(data) {
			val = uint32(data[i])<<8 | uint32(data[i+1])
		} else {
			val = uint32(data[i]) << 8
		}
		sum += val
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if ^uint16(sum) != 0 {
		t.Fatal("checksum validation failed")
	}
}

func TestBuildICMPv4UnreachableChecksum(t *testing.T) {
	origSrc := netip.AddrFrom4([4]byte{10, 0, 0, 2})
	origDst := netip.AddrFrom4([4]byte{8, 8, 8, 8})

	origPayload := make([]byte, 28)
	origPayload[0] = 0x45
	src4 := origSrc.As4()
	dst4 := origDst.As4()
	copy(origPayload[12:16], src4[:])
	copy(origPayload[16:20], dst4[:])

	pkt := BuildICMPv4Unreachable(origSrc, origDst, origPayload)

	validateChecksum(t, pkt[:20])
	validateChecksum(t, pkt[20:])
}

func TestBuildICMPv6Checksum(t *testing.T) {
	origSrc := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	origDst := netip.AddrFrom16([16]byte{0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	origPayload := make([]byte, 48)
	origPayload[0] = 0x60
	src16slice := origSrc.As16()
	dst16slice := origDst.As16()
	copy(origPayload[8:24], src16slice[:])
	copy(origPayload[24:40], dst16slice[:])

	pkt := BuildICMPv6Unreachable(origSrc, origDst, origPayload)

	// ICMPv6 checksum is at bytes 42-44, validate it
	var sum uint32
	src16 := origDst.As16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(src16[i])<<8 | uint32(src16[i+1])
	}
	dst16 := origSrc.As16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst16[i])<<8 | uint32(dst16[i+1])
	}
	sum += uint32(len(pkt[40:]))
	sum += 58
	for i := 40; i < len(pkt); i += 2 {
		var val uint32
		if i+1 < len(pkt) {
			val = uint32(pkt[i])<<8 | uint32(pkt[i+1])
		} else {
			val = uint32(pkt[i]) << 8
		}
		sum += val
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if ^uint16(sum) != 0 {
		t.Fatal("ICMPv6 checksum validation failed")
	}
}
