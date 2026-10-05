//go:build windows

package tun

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// outboundGuard keeps Windows to the binding of autoOutboundsInterface, which
// keeps Xray's own connections out of the TUN. With weak host send or
// forwarding on for an IP version on the bound interface, Windows sends them
// where the routes lead, into the TUN, from that interface's address, and
// drops what comes back to that address through the TUN, so they stall.
//
// For the IP versions routed to the TUN, weak host send is turned off on the
// bound interface while the TUN runs, and turned on again when the TUN stops
// or another interface takes over. Forwarding is what Mobile Hotspot and
// Internet Connection Sharing need, so it is only reported.
type outboundGuard struct {
	sync.Mutex
	families  []winipcfg.AddressFamily
	luid      winipcfg.LUID            // of the interface last checked
	turnedOff []winipcfg.AddressFamily // where weak host send was turned off on it
	reported  string                   // the forwarding problem last logged
	stopped   bool
}

// check turns weak host send off on the bound interface, and returns what is
// wrong if forwarding is on there.
func (g *outboundGuard) check() string {
	g.Lock()
	defer g.Unlock()
	if g.stopped {
		return ""
	}
	var luid winipcfg.LUID
	var name string
	if iface := updater.Get(); iface != nil {
		luid, _ = winipcfg.LUIDFromIndex(uint32(iface.Index))
		name = iface.Name
	}
	if luid != g.luid {
		g.restoreLocked()
		g.luid = luid
	}
	if luid == 0 {
		return ""
	}
	var forwarding []string
	for _, family := range g.families {
		row, err := luid.IPInterface(family)
		if err != nil {
			continue // the interface lacks that IP version
		}
		if row.ForwardingEnabled {
			forwarding = append(forwarding, familyName(family))
		}
		if !row.WeakHostSend {
			continue
		}
		if err := setWeakHostSend(row, false); err != nil {
			errors.LogWarningInner(context.Background(), err, "[tun] unable to turn weak host send off for ", familyName(family), " on ", name)
			continue
		}
		if !slices.Contains(g.turnedOff, family) {
			g.turnedOff = append(g.turnedOff, family)
		}
		errors.LogInfo(context.Background(), "[tun] weak host send turned off for ", familyName(family), " on ", name, " while the TUN runs, as Windows would ignore autoOutboundsInterface")
	}
	if len(forwarding) > 0 {
		return "forwarding is on for " + strings.Join(forwarding, " and ") + " on " + name + ", as Mobile Hotspot and Internet Connection Sharing turn it on, so Windows ignores autoOutboundsInterface there, and Xray's own connections go into the TUN and stall"
	}
	return ""
}

// recheck is check for a running TUN, which logs a forwarding problem once.
func (g *outboundGuard) recheck() {
	problem := g.check()
	g.Lock()
	changed := problem != g.reported
	g.reported = problem
	g.Unlock()
	if changed && problem != "" {
		errors.LogError(context.Background(), "[tun] ", problem)
	}
}

// restore turns weak host send on again where check turned it off, for good.
func (g *outboundGuard) restore() {
	g.Lock()
	defer g.Unlock()
	g.restoreLocked()
	g.stopped = true
}

func (g *outboundGuard) restoreLocked() {
	for _, family := range g.turnedOff {
		if row, err := g.luid.IPInterface(family); err == nil {
			if err := setWeakHostSend(row, true); err != nil {
				errors.LogWarningInner(context.Background(), err, "[tun] unable to turn weak host send on again for ", familyName(family))
			}
		}
	}
	g.turnedOff = nil
}

func setWeakHostSend(row *winipcfg.MibIPInterfaceRow, on bool) error {
	row.WeakHostSend = on
	if row.Family == windows.AF_INET {
		row.SitePrefixLength = 0 // as SetIpInterfaceEntry requires for IPv4
	}
	return row.Set()
}

func familyName(family winipcfg.AddressFamily) string {
	if family == windows.AF_INET {
		return "IPv4"
	}
	return "IPv6"
}
