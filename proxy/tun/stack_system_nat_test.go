package tun

import (
	"net/netip"
	"testing"
)

func TestTCPNAT_LookupAndAllocate(t *testing.T) {
	nat := NewTCPNAT()
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 12345)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)

	// First allocation
	port1, err := nat.LookupOrAllocate(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if port1 == 0 {
		t.Fatal("port should be allocated")
	}

	// Same src+dst returns same port
	port2, err := nat.LookupOrAllocate(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if port1 != port2 {
		t.Fatal("should return same port for same connection")
	}

	// Reverse lookup
	backSrc, backDst, ok := nat.LookupBack(port1)
	if !ok {
		t.Fatal("should find back mapping")
	}
	if backSrc != src || backDst != dst {
		t.Fatal("back mapping should match original")
	}
}

func TestTCPNAT_DifferentDestinations(t *testing.T) {
	nat := NewTCPNAT()
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 12345)
	dst1 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)
	dst2 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53)

	port1, _ := nat.LookupOrAllocate(src, dst1)
	port2, _ := nat.LookupOrAllocate(src, dst2)
	if port1 == port2 {
		t.Fatal("different destinations should get different ports")
	}

	_, backDst1, _ := nat.LookupBack(port1)
	if backDst1 != dst1 {
		t.Fatal("port1 should map to dst1, got", backDst1)
	}
	_, backDst2, _ := nat.LookupBack(port2)
	if backDst2 != dst2 {
		t.Fatal("port2 should map to dst2, got", backDst2)
	}
}

func TestTCPNAT_Delete(t *testing.T) {
	nat := NewTCPNAT()
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 12345)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)

	port, _ := nat.LookupOrAllocate(src, dst)
	nat.Delete(port)

	_, _, ok := nat.LookupBack(port)
	if ok {
		t.Fatal("should not find after delete")
	}

	// Re-allocation after delete should work
	port2, _ := nat.LookupOrAllocate(src, dst)
	if port2 != port {
		t.Fatal("should reuse freed port")
	}
}

func TestUDPNAT(t *testing.T) {
	nat := NewUDPNAT()
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 12345)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)

	port1, _ := nat.LookupOrAllocate(src, dst)
	port2, _ := nat.LookupOrAllocate(src, dst)
	if port1 != port2 {
		t.Fatal("UDP NAT should return same port")
	}

	// Reverse lookup
	backSrc, backDst, ok := nat.LookupBack(port1)
	if !ok {
		t.Fatal("should find back mapping")
	}
	if backSrc != src || backDst != dst {
		t.Fatal("back mapping mismatch")
	}
}

func TestUDPNAT_Delete(t *testing.T) {
	nat := NewUDPNAT()
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 12345)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)

	port, _ := nat.LookupOrAllocate(src, dst)
	nat.Delete(port)

	_, _, ok := nat.LookupBack(port)
	if ok {
		t.Fatal("should not find after delete")
	}
}
