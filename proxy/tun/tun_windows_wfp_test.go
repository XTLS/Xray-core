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

	var ports fwpRange0
	check("FWP_RANGE0",
		[]uintptr{unsafe.Sizeof(ports), unsafe.Offsetof(ports.high)},
		[]uintptr{32, 16}, []uintptr{16, 8})

	var v4 fwpV4AddrAndMask
	check("FWP_V4_ADDR_AND_MASK",
		[]uintptr{unsafe.Sizeof(v4), unsafe.Offsetof(v4.mask)},
		[]uintptr{8, 4}, []uintptr{8, 4})

	var v6 fwpV6AddrAndMask
	check("FWP_V6_ADDR_AND_MASK",
		[]uintptr{unsafe.Sizeof(v6), unsafe.Offsetof(v6.prefixLength)},
		[]uintptr{17, 16}, []uintptr{17, 16})

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
	// Each with a sublayer of its own.
	for _, c := range []struct {
		values         []string
		route4, route6 bool
	}{
		{[]string{"dns", "misconfigtun", "all", "tcp/443", "udp/1000-2000", "tcp", "icmp", "10-20", "1-65535"}, false, false},
		// CIDRs, and the local network's addresses.
		{[]string{"1.1.1.0/24:tcp/80", "[2001:db8::/32]:udp/5000-6000", "[::/0]:icmp", "8.8.8.8/32:all", "[2000::/3]:misconfigtun", "9.9.9.9/32:dns"}, true, false},
		{[]string{"allexceptlan", "udp/1000-2000", "icmp", "192.168.1.5/32:all"}, true, false},
		{[]string{"0.0.0.0/0:allexceptlan", "[::/0]:all", "[::/0]:windnsclient", "1.0.0.0/8:windnsclient"}, true, true},
		{[]string{"[::/0]:allexceptlan", "0.0.0.0/0:misconfigtun", "10.0.0.0/8:allexceptlan", "1.0.0.0/8:allexceptlan"}, false, true},
	} {
		leaks, err := ExpandWfpBlockLeak(c.values)
		if err != nil {
			t.Fatal(err)
		}
		if err := addLeakFilters(engine, loopback, newLeakFilters(leaks, c.route4, c.route6)); err != nil {
			skipUnlessElevated(err)
		}
	}
}

func TestNewLeakFilters(t *testing.T) {
	for _, c := range []struct {
		values         []string
		route4, route6 bool
		blocked        string
		systemDNS      bool
	}{
		{[]string{"dns", "misconfigtun"}, true, false, "53, 853, windnsclient, [::/0]:misconfigtun", true},
		{[]string{"tcp/853", "udp/853", "misconfigtun"}, true, true, "tcp/853, udp/853", false},
		{[]string{"all"}, true, true, "all", true},
		{[]string{"all", "misconfigtun"}, true, true, "all", true},
		{[]string{"misconfigtun"}, true, false, "[::/0]:misconfigtun", false},
		{[]string{"misconfigtun"}, false, true, "0.0.0.0/0:misconfigtun", false},
		{[]string{"misconfigtun"}, false, false, "misconfigtun", false},
		{[]string{"tcp/10-20", "udp", "icmp"}, true, true, "tcp/10-20, udp, icmp", true},
		{[]string{"tcp/54-60", "icmp", "54-60"}, true, true, "tcp/54-60, icmp, 54-60", false},
		{[]string{"allexceptlan"}, true, true, "allexceptlan, 53, 853, windnsclient", true},
		{[]string{"allexceptlan", "all"}, true, true, "allexceptlan, 53, 853, windnsclient, all", true},
		{[]string{"misconfigtun", "allexceptlan"}, true, false, "[::/0]:misconfigtun, allexceptlan, 53, 853, windnsclient", true},
		// Limited to the addresses of a CIDR.
		{[]string{"0.0.0.0/0:TCP/10-20", "[::/0]:udp", "0.0.0.0/0:icmp"}, true, true, "0.0.0.0/0:tcp/10-20, [::/0]:udp, 0.0.0.0/0:icmp", true},
		{[]string{"[::/0]:tcp/54-60", "[::/0]:icmp"}, true, true, "[::/0]:tcp/54-60, [::/0]:icmp", false},
		{[]string{"0.0.0.0/0:windnsclient"}, true, true, "0.0.0.0/0:windnsclient", true},
		{[]string{"1.1.1.0/24:53"}, true, true, "1.1.1.0/24:53", true},
		{[]string{"[::/0]:all"}, true, false, "[::/0]:all", true},
		{[]string{"0.0.0.0/0:allexceptlan", "[::/0]:all"}, true, true, "0.0.0.0/0:allexceptlan, 0.0.0.0/0:53, 0.0.0.0/0:853, 0.0.0.0/0:windnsclient, [::/0]:all", true},
		{[]string{"0.0.0.0/0:misconfigtun"}, true, false, "", false},
		{[]string{"[::/0]:misconfigtun"}, true, false, "[::/0]:misconfigtun", false},
		{[]string{"[2000::/3]:misconfigtun", "1.0.0.0/8:misconfigtun"}, true, false, "[2000::/3]:misconfigtun", false},
		{[]string{"misconfigtun", "[::/0]:misconfigtun"}, true, false, "[::/0]:misconfigtun", false},
		{[]string{"0.0.0.0/0:misconfigtun", "[::/0]:allexceptlan"}, false, true, "0.0.0.0/0:misconfigtun, [::/0]:allexceptlan, [::/0]:53, [::/0]:853, [::/0]:windnsclient", true},
	} {
		leaks, err := ExpandWfpBlockLeak(c.values)
		if err != nil {
			t.Fatal(err)
		}
		block := newLeakFilters(leaks, c.route4, c.route6)
		if got := block.String(); got != c.blocked {
			t.Errorf("%v: String() = %q, want %q", c.values, got, c.blocked)
		}
		if got := block.systemDNS(); got != c.systemDNS {
			t.Errorf("%v: systemDNS() = %v", c.values, got)
		}
	}
	// Without the port 53 values "allexceptlan" brings along, a resolver on
	// the local network, like the router's, stays reachable.
	if (leakFilters{{name: "allexceptlan"}}).systemDNS() {
		t.Error("systemDNS() = true with the local network open")
	}
}

func TestLanWithin(t *testing.T) {
	prefixes := func(cidrs ...string) []netip.Prefix {
		var prefixes []netip.Prefix
		for _, cidr := range cidrs {
			prefixes = append(prefixes, netip.MustParsePrefix(cidr))
		}
		return prefixes
	}
	for _, c := range []struct {
		within, lan []netip.Prefix
	}{
		{nil, nil},
		{prefixes("0.0.0.0/0"), prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32")},
		{prefixes("::/0"), prefixes("fc00::/7", "fe80::/10", "ff00::/8")},
		{prefixes("1.0.0.0/8", "10.1.0.0/16"), prefixes("10.1.0.0/16")},
		{prefixes("192.0.0.0/2"), prefixes("192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32")},
		{prefixes("2000::/3", "fe80::/64", "fe80::/10"), prefixes("fe80::/64", "fe80::/10")},
		{prefixes("8.8.8.8/32", "2001:db8::/32"), nil},
	} {
		if got := lanWithin(c.within...); !slices.Equal(got, c.lan) {
			t.Errorf("%v: got %v, want %v", c.within, got, c.lan)
		}
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
		// Local resolvers, reachable over loopback whatever is blocked.
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::ffff:127.0.0.53"),
		netip.MustParseAddr("::1"),
	}
	// Only to the addresses of their CIDRs, if any, and "misconfigtun" over
	// an IP version without routes to the TUN blocks DNS as well.
	for _, c := range []struct {
		values         []string
		route4, route6 bool
		want           []string
	}{
		{[]string{"dns"}, true, true, []string{"8.8.8.8", "2001:db8::53"}},
		{[]string{"0.0.0.0/0:53"}, true, true, []string{"8.8.8.8"}},
		{[]string{"8.8.8.0/24:windnsclient", "[2001:db8::/32]:tcp/853"}, true, true, []string{"8.8.8.8"}},
		{[]string{"[2001:db8::53/128]:all", "9.9.9.9/32:53"}, true, true, []string{"2001:db8::53"}},
		{[]string{"misconfigtun"}, true, false, []string{"2001:db8::53"}},
		{[]string{"misconfigtun"}, true, true, nil},
		{[]string{"tcp/853", "udp/5353", "icmp", "10.0.0.0/8:all"}, true, true, nil},
		{[]string{"[::/0]:allexceptlan"}, true, true, []string{"2001:db8::53"}},
	} {
		leaks, err := ExpandWfpBlockLeak(c.values)
		if err != nil {
			t.Fatal(err)
		}
		var want []netip.Addr
		for _, server := range c.want {
			want = append(want, netip.MustParseAddr(server))
		}
		if got := dnsOutsideTUN(servers, prefixes, newLeakFilters(leaks, c.route4, c.route6)); !slices.Equal(got, want) {
			t.Errorf("%v: got %v, want %v", c.values, got, want)
		}
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
