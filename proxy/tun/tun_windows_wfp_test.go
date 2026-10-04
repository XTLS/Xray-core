//go:build windows

package tun

import (
	"context"
	go_errors "errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// The WFP structures are handed to fwpuclnt.dll as they are, so their layout
// has to match what MSVC produces for 64-bit and for 32-bit Windows.
func TestWFPStructLayout(t *testing.T) {
	check := func(name string, got, want64, want32 []uintptr) {
		t.Helper()
		want := want32
		if unsafe.Sizeof(uintptr(0)) == 8 {
			want = want64
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: size and offsets are %v, want %v", name, got, want)
		}
	}

	var blob fwpByteBlob
	check("FWP_BYTE_BLOB",
		[]uintptr{unsafe.Sizeof(blob), unsafe.Offsetof(blob.data)},
		[]uintptr{16, 8}, []uintptr{8, 4})

	var value fwpValue0
	check("FWP_VALUE0",
		[]uintptr{unsafe.Sizeof(value), unsafe.Offsetof(value.value)},
		[]uintptr{16, 8}, []uintptr{8, 4})

	var display fwpmDisplayData0
	check("FWPM_DISPLAY_DATA0",
		[]uintptr{unsafe.Sizeof(display), unsafe.Offsetof(display.description)},
		[]uintptr{16, 8}, []uintptr{8, 4})

	var action fwpmAction0
	check("FWPM_ACTION0",
		[]uintptr{unsafe.Sizeof(action), unsafe.Offsetof(action.filterType)},
		[]uintptr{20, 4}, []uintptr{20, 4})

	var cond fwpmFilterCondition0
	check("FWPM_FILTER_CONDITION0",
		[]uintptr{unsafe.Sizeof(cond), unsafe.Offsetof(cond.matchType), unsafe.Offsetof(cond.conditionValue)},
		[]uintptr{40, 16, 24}, []uintptr{28, 16, 20})

	var session fwpmSession0
	check("FWPM_SESSION0",
		[]uintptr{
			unsafe.Sizeof(session), unsafe.Offsetof(session.displayData), unsafe.Offsetof(session.flags),
			unsafe.Offsetof(session.txnWaitTimeoutInMSec), unsafe.Offsetof(session.processID), unsafe.Offsetof(session.sid),
			unsafe.Offsetof(session.username), unsafe.Offsetof(session.kernelMode),
		},
		[]uintptr{72, 16, 32, 36, 40, 48, 56, 64},
		[]uintptr{48, 16, 24, 28, 32, 36, 40, 44})

	var sublayer fwpmSublayer0
	check("FWPM_SUBLAYER0",
		[]uintptr{
			unsafe.Sizeof(sublayer), unsafe.Offsetof(sublayer.displayData), unsafe.Offsetof(sublayer.flags),
			unsafe.Offsetof(sublayer.providerKey), unsafe.Offsetof(sublayer.providerData), unsafe.Offsetof(sublayer.weight),
		},
		[]uintptr{72, 16, 32, 40, 48, 64},
		[]uintptr{44, 16, 24, 28, 32, 40})

	var filter fwpmFilter0
	check("FWPM_FILTER0",
		[]uintptr{
			unsafe.Sizeof(filter), unsafe.Offsetof(filter.displayData), unsafe.Offsetof(filter.flags),
			unsafe.Offsetof(filter.providerKey), unsafe.Offsetof(filter.providerData), unsafe.Offsetof(filter.layerKey),
			unsafe.Offsetof(filter.subLayerKey), unsafe.Offsetof(filter.weight), unsafe.Offsetof(filter.numFilterConditions),
			unsafe.Offsetof(filter.filterCondition), unsafe.Offsetof(filter.action), unsafe.Offsetof(filter.providerContextKey),
			unsafe.Offsetof(filter.reserved), unsafe.Offsetof(filter.filterID), unsafe.Offsetof(filter.effectiveWeight),
		},
		[]uintptr{200, 16, 32, 40, 48, 64, 80, 96, 112, 120, 128, 152, 168, 176, 184},
		[]uintptr{152, 16, 24, 28, 32, 40, 56, 72, 80, 84, 88, 112, 128, 136, 144})
}

// TestLeakFiltersAccepted has WFP validate the filters by adding them inside a
// transaction that is then aborted, which leaves the system untouched. Adding
// filters requires an elevated process.
func TestLeakFiltersAccepted(t *testing.T) {
	skipUnlessElevated := func(err error) {
		t.Helper()
		if go_errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skipf("WFP filters can only be added by an elevated process: %v", err)
		}
		t.Fatal(err)
	}

	engine, err := openWFPEngine()
	if err != nil {
		skipUnlessElevated(err)
	}
	defer closeWFPEngine(engine)
	if err := fwpmResult(procFwpmTransactionBegin0.Call(uintptr(engine), 0)); err != nil {
		skipUnlessElevated(err)
	}
	defer procFwpmTransactionAbort0.Call(uintptr(engine))

	// Any interface stands in for the TUN; the loopback one always exists.
	loopback, err := winipcfg.LUIDFromIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := addLeakFilters(engine, loopback, true, true, true); err != nil {
		skipUnlessElevated(err)
	}
}

func TestDNSClientSID(t *testing.T) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\Dnscache`)
	if err != nil {
		t.Fatal(err)
	}
	if sid.String() != dnsClientSID {
		t.Errorf(`NT SERVICE\Dnscache is %v, not %v`, sid, dnsClientSID)
	}
}

func TestDNSOutsideTUN(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.1/30"), // gateway, not masked
		netip.MustParsePrefix("203.0.113.0/24"),  // route
	}
	servers := []netip.Addr{
		netip.MustParseAddr("198.51.100.2"),
		netip.MustParseAddr("203.0.113.53"),
		netip.MustParseAddr("::ffff:203.0.113.54"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2001:db8::53"),
	}
	want := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:db8::53")}
	if got := dnsOutsideTUN(servers, prefixes); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveOnOwn(t *testing.T) {
	internet.SkipDNSServers([]netip.Addr{netip.MustParseAddr("::ffff:203.0.113.53")})
	t.Cleanup(func() { internet.SkipDNSServers(nil) })
	preferGo, dial := net.DefaultResolver.PreferGo, net.DefaultResolver.Dial
	saved := resolveOnOwn()
	t.Cleanup(saved.restore)
	if !net.DefaultResolver.PreferGo || net.DefaultResolver.Dial == nil {
		t.Fatal("net.DefaultResolver is unchanged")
	}
	if _, err := net.DefaultResolver.Dial(context.Background(), "udp", "203.0.113.53:53"); err == nil {
		t.Error("the TUN's DNS server was not skipped")
	}
	conn, err := net.DefaultResolver.Dial(context.Background(), "udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	saved.restore()
	if net.DefaultResolver.PreferGo != preferGo || (net.DefaultResolver.Dial == nil) != (dial == nil) {
		t.Error("net.DefaultResolver is not restored")
	}
}

// TestTunOnlyDNS checks that a DNS server another interface uses as well is
// not skipped, while one of the TUN alone is.
func TestTunOnlyDNS(t *testing.T) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		t.Fatal(err)
	}
	var other netip.Addr
	for _, adapter := range adapters {
		if adapter.OperStatus == winipcfg.IfOperStatusUp && adapter.FirstGatewayAddress != nil && adapter.FirstDNSServerAddress != nil {
			other, _ = netip.AddrFromSlice(adapter.FirstDNSServerAddress.Address.IP())
			other = other.Unmap()
			break
		}
	}
	if !other.IsValid() {
		t.Skip("no interface with a gateway and a DNS server")
	}
	tunOnly := netip.MustParseAddr("203.0.113.53")
	// LUID 0 is no interface, so every one counts as another.
	got, err := tunOnlyDNS(0, []netip.Addr{other, tunOnly})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []netip.Addr{tunOnly}) {
		t.Errorf("got %v, want [%v]", got, tunOnly)
	}
}

func TestFlushDNSCache(t *testing.T) {
	if err := flushDNSCache(); err != nil {
		t.Fatal(err)
	}
}
