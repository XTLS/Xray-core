package net

import (
	"net"
	"net/netip"
)

var (
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalUsePrefix  = netip.MustParsePrefix("64:ff9b:1::/48")
)

// IsNAT64 reports whether addr is an IPv6 address synthesized by DNS64/NAT64 (RFC 6052, RFC 8215).
func IsNAT64(addr netip.Addr) bool {
	return nat64WellKnownPrefix.Contains(addr) || nat64LocalUsePrefix.Contains(addr)
}

// FilterNAT64 removes NAT64-synthesized addresses from ips.
func FilterNAT64(ips []net.IP) []net.IP {
	filtered := ips[:0:0]
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok && IsNAT64(addr) {
			continue
		}
		filtered = append(filtered, ip)
	}
	return filtered
}
