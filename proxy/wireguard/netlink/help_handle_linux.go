package netlink

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func (h *Handle) EmptyRouteTableIndex(family, from int) (out int, err error) {
	r := &netlink.Route{Table: from}
	for ; r.Table >= 0; r.Table-- {
		routeList, fErr := netlink.RouteListFiltered(family, r, netlink.RT_FILTER_TABLE)
		if len(routeList) == 0 || fErr != nil {
			break
		}
	}
	if r.Table < 0 {
		return 0, fmt.Errorf("failed to find available family[%d] from[%d] table index", family, from)
	}
	return r.Table, nil
}
