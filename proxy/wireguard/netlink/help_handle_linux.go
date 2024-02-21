package netlink

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func (h *Handle) EmptyRouteTableIndex(family int) (out int, err error) {
	// maximum table index is 1023
	r := &netlink.Route{Table: 1023}
	for ; r.Table >= 0; r.Table-- {
		routeList, fErr := netlink.RouteListFiltered(family, r, netlink.RT_FILTER_TABLE)
		if len(routeList) == 0 || fErr != nil {
			break
		}
	}
	if r.Table < 0 {
		return 0, fmt.Errorf("failed to find available family[%d] table index", family)
	}
	return r.Table, nil
}
