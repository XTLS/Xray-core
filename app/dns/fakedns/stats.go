package fakedns

import "github.com/xtls/xray-core/features/dns"

func (h *Holder) GetFakeDNSStats() []dns.FakeDNSPoolStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.domainToIP == nil || h.ipRange == nil {
		return nil
	}
	cache, ok := h.domainToIP.(interface{ Usage() (int, int) })
	if !ok {
		return nil
	}
	used, capacity := cache.Usage()
	return []dns.FakeDNSPoolStats{{IPPool: h.ipRange.String(), Used: uint64(used), Capacity: uint64(capacity)}}
}

func (h *HolderMulti) GetFakeDNSStats() []dns.FakeDNSPoolStats {
	var result []dns.FakeDNSPoolStats
	for _, holder := range h.holders {
		stats := holder.GetFakeDNSStats()
		if len(stats) == 0 {
			return nil
		}
		result = append(result, stats...)
	}
	return result
}
