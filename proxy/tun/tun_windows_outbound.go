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
	families   []winipcfg.AddressFamily
	luid       winipcfg.LUID            // of the interface last checked
	name       string                   // of that interface
	turnedOff  []winipcfg.AddressFamily // where weak host send was turned off on it
	forwarding bool                     // whether forwarding was on there
	stopped    bool
}

// check turns weak host send off on the bound interface, and warns when
// forwarding comes on there, but not again while it stays on.
func (g *outboundGuard) check() {
	g.Lock()
	defer g.Unlock()
	if g.stopped {
		return
	}
	var luid winipcfg.LUID
	var name string
	if iface := updater.Get(); iface != nil {
		luid, _ = winipcfg.LUIDFromIndex(uint32(iface.Index))
		name = iface.Name
	}
	if luid != g.luid {
		g.restoreLocked()
		g.luid, g.name = luid, name
		g.forwarding = false // to warn about the new interface as well
	}
	if luid == 0 {
		return
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
			errors.LogInfo(context.Background(), "[tun] weak host send turned off for ", familyName(family), " on ", name, " while the TUN runs, as Windows would ignore autoOutboundsInterface")
		}
	}
	wasOn := g.forwarding
	g.forwarding = len(forwarding) > 0
	if g.forwarding && !wasOn {
		errors.LogWarning(context.Background(), "[tun] forwarding is on for ", strings.Join(forwarding, " and "), " on ", name, " (Mobile Hotspot and Internet Connection Sharing turn it on), so Windows ignores autoOutboundsInterface there, and Xray's own connections go into the TUN and stall: turn the hotspot off, or have it share the TUN instead of ", name)
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
		row, err := g.luid.IPInterface(family)
		if err == nil {
			err = setWeakHostSend(row, true)
		}
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "[tun] unable to turn weak host send on again for ", familyName(family), " on ", g.name)
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
