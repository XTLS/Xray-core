package geoip

// CIDRList is an alias of []*CIDR to provide sort.Interface.
type CIDRList []*CIDR

// Len implements sort.Interface.
func (l *CIDRList) Len() int {
	return len(*l)
}

// Less implements sort.Interface.
func (l *CIDRList) Less(i int, j int) bool {
	ci := (*l)[i]
	cj := (*l)[j]

	if len(ci.Ip) < len(cj.Ip) {
		return true
	}

	if len(ci.Ip) > len(cj.Ip) {
		return false
	}

	for k := 0; k < len(ci.Ip); k++ {
		if ci.Ip[k] < cj.Ip[k] {
			return true
		}

		if ci.Ip[k] > cj.Ip[k] {
			return false
		}
	}

	return ci.Prefix < cj.Prefix
}

// Swap implements sort.Interface.
func (l *CIDRList) Swap(i int, j int) {
	(*l)[i], (*l)[j] = (*l)[j], (*l)[i]
}
