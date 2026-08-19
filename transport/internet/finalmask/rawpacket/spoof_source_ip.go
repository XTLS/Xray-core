package rawpacket

import (
	"net/netip"
	"sync/atomic"
)

type SourceIPRotator struct {
	ips  []netip.Addr
	next atomic.Uint64
}

func NewSourceIPRotator(ips []netip.Addr) *SourceIPRotator {
	if len(ips) == 0 {
		return nil
	}
	return &SourceIPRotator{ips: ips}
}

func (r *SourceIPRotator) Next() netip.Addr {
	if r == nil || len(r.ips) == 0 {
		return netip.Addr{}
	}
	i := r.next.Add(1) - 1
	return r.ips[i%uint64(len(r.ips))]
}

func (r *SourceIPRotator) Len() int {
	if r == nil {
		return 0
	}
	return len(r.ips)
}
