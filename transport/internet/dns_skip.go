package internet

import (
	"net/netip"
	"slices"
	"sync/atomic"
)

var skippedDNSServers atomic.Pointer[[]netip.Addr]

// SkipDNSServers has the queries Xray sends to the system's DNS servers on its
// own, like those of localdns, skip servers until it is called again. The DNS
// servers of a TUN are only meant for what goes through it: queried by Xray
// itself they lead back into it, or nowhere.
func SkipDNSServers(servers []netip.Addr) {
	skipped := make([]netip.Addr, len(servers))
	for i, server := range servers {
		skipped[i] = server.Unmap()
	}
	skippedDNSServers.Store(&skipped)
}

// IsSkippedDNSServer reports whether address, a DNS server as host:port, is to
// be skipped, see SkipDNSServers.
func IsSkippedDNSServer(address string) bool {
	skipped := skippedDNSServers.Load()
	if skipped == nil {
		return false
	}
	server, err := netip.ParseAddrPort(address)
	return err == nil && slices.Contains(*skipped, server.Addr().Unmap())
}
