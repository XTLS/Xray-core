package masque

import (
	"net/netip"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type addressPool struct {
	mu     sync.Mutex
	prefix netip.Prefix
	server netip.Addr
	first  netip.Addr
	last   netip.Addr
	next   netip.Addr
	used   map[netip.Addr]struct{}
}

func newAddressPool(address netip.Prefix) (*addressPool, error) {
	server := address.Addr()
	if server.Is4In6() || server.Zone() != "" {
		return nil, errors.New("invalid address ", address)
	}
	prefix := address.Masked()
	last := lastAddr(prefix)
	if server == prefix.Addr() || server.Is4() && server == last {
		return nil, errors.New("address ", address, " is not a host address")
	}
	if server.Is4() {
		last = last.Prev()
	}
	first := prefix.Addr().Next()
	if first == last {
		return nil, errors.New("address ", address, " leaves no addresses to assign")
	}
	return &addressPool{
		prefix: prefix,
		server: server,
		first:  first,
		last:   last,
		next:   first,
		used:   make(map[netip.Addr]struct{}),
	}, nil
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().AsSlice()
	for i := prefix.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

func (p *addressPool) allocate() (netip.Addr, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr := p.next; ; {
		next := addr.Next()
		if addr == p.last {
			next = p.first
		}
		if _, found := p.used[addr]; !found && addr != p.server {
			p.used[addr] = struct{}{}
			p.next = next
			return addr, true
		}
		if next == p.next {
			return netip.Addr{}, false
		}
		addr = next
	}
}

func (p *addressPool) release(addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, addr)
}
