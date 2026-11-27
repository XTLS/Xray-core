//go:build (linux && !android) || windows

package net

import (
	"net/netip"
	"slices"
)

// localProxyLimit is the number of local proxy addresses that a process finder keeps.
const localProxyLimit = 4

// localProxies has the loopback addresses that programs connected to, the newest first: the
// addresses of local proxies such as the SOCKS and HTTP inbounds. The socket of such a program has
// the address of the proxy as its remote address and a loopback address as its source address.
type localProxies []netip.AddrPort

func (p *localProxies) add(address netip.AddrPort) {
	*p = mruPush(*p, address, localProxyLimit)
}

// candidates returns the probable remote addresses of the TCP socket with the source address
// local: first remote, then for a loopback source the known local proxies.
func (p localProxies) candidates(local, remote netip.AddrPort) []netip.AddrPort {
	candidates := make([]netip.AddrPort, 0, len(p)+1)
	if remote.IsValid() && remote.Addr().Is4() == local.Addr().Is4() {
		candidates = append(candidates, remote)
	}
	if local.Addr().IsLoopback() {
		for _, proxy := range p {
			if proxy != remote && proxy.Addr().Is4() == local.Addr().Is4() {
				candidates = append(candidates, proxy)
			}
		}
	}
	return candidates
}

// mruPush puts value at the start of list and removes its other copies. The result has at most
// limit values.
func mruPush[T comparable](list []T, value T, limit int) []T {
	list = slices.DeleteFunc(list, func(item T) bool { return item == value })
	list = slices.Insert(list, 0, value)
	return list[:min(len(list), limit)]
}
