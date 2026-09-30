//go:build windows

package tun

import (
	"net/netip"
	"os"
	"runtime"
	"slices"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")
	moddnsapi   = windows.NewLazySystemDLL("dnsapi.dll")

	procFwpmEngineOpen0           = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmSubLayerAdd0          = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmGetAppIdFromFileName0 = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procDnsFlushResolverCache     = moddnsapi.NewProc("DnsFlushResolverCache")
)

// fwptypes.h and fwpmtypes.h
const (
	rpcCAuthnWinNT                 = 10 // RPC_C_AUTHN_WINNT
	fwpmSessionFlagDynamic         = 1  // FWPM_SESSION_FLAG_DYNAMIC
	fwpmFilterFlagClearActionRight = 8  // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT

	fwpUint8                  = 1  // FWP_UINT8
	fwpUint16                 = 2  // FWP_UINT16
	fwpUint32                 = 3  // FWP_UINT32
	fwpUint64                 = 4  // FWP_UINT64
	fwpByteArray16Type        = 11 // FWP_BYTE_ARRAY16_TYPE
	fwpByteBlobType           = 12 // FWP_BYTE_BLOB_TYPE
	fwpSecurityDescriptorType = 14 // FWP_SECURITY_DESCRIPTOR_TYPE

	fwpMatchEqual       = 0 // FWP_MATCH_EQUAL
	fwpMatchFlagsAllSet = 6 // FWP_MATCH_FLAGS_ALL_SET

	fwpConditionFlagIsLoopback = 1 // FWP_CONDITION_FLAG_IS_LOOPBACK

	fwpActionBlock  = 0x1001 // FWP_ACTION_BLOCK
	fwpActionPermit = 0x1002 // FWP_ACTION_PERMIT
)

// fwpmu.h
var (
	fwpmLayerALEAuthConnectV4    = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	fwpmLayerALEAuthConnectV6    = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	fwpmLayerALEAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	fwpmLayerALEAuthRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	fwpmConditionFlags              = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	fwpmConditionIPArrivalInterface = windows.GUID{Data1: 0x618a9b6d, Data2: 0x386b, Data3: 0x4136, Data4: [8]byte{0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd}}
	fwpmConditionIPLocalInterface   = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	fwpmConditionIPLocalPort        = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}} // also FWPM_CONDITION_ICMP_TYPE
	fwpmConditionIPNexthopInterface = windows.GUID{Data1: 0x93ae8f5b, Data2: 0x7f6f, Data3: 0x4719, Data4: [8]byte{0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04}}
	fwpmConditionIPProtocol         = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	fwpmConditionIPRemoteAddress    = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	fwpmConditionIPRemotePort       = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}} // also FWPM_CONDITION_ICMP_CODE
	fwpmConditionALEAppID           = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	fwpmConditionALEUserID          = windows.GUID{Data1: 0xaf043a0a, Data2: 0xb34d, Data3: 0x4f86, Data4: [8]byte{0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66}}
)

// dnsClientSID is the SID of Windows' DNS Client service, NT SERVICE\Dnscache.
// Service SIDs derive from the service name, so it is the same everywhere (sc
// showsid dnscache).
const dnsClientSID = "S-1-5-80-859482183-879914841-863379149-1145462774-2388618682"

// ff02::1:2, where DHCPv6 clients send to. A package-level variable never
// moves, so conditions may refer to it through uintptr.
var ipv6AllDHCPv6Servers = [16]byte{0xff, 0x02, 13: 0x01, 15: 0x02}

type fwpByteBlob struct {
	size uint32
	data *byte
}

// fwpValue0 is FWP_VALUE0 as well as FWP_CONDITION_VALUE0. Their union holds
// a scalar of at most 32 bits, or a pointer for the larger types.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   uint32 // C aligns the following union to 8 bytes, as it holds a UINT64
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	_                   [8 - unsafe.Sizeof(uintptr(0))]byte // and filterId as well, also on 32-bit
	filterID            uint64
	effectiveWeight     fwpValue0
}

// fwpmResult converts the DWORD status the Fwpm functions return.
func fwpmResult(r1, _ uintptr, _ error) error {
	if r1 != 0 {
		return windows.Errno(r1)
	}
	return nil
}

func utf16Ptr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func condition(field *windows.GUID, typ uint32, value uintptr) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:       *field,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{typ: typ, value: value},
	}
}

// blockLeaks keeps traffic from leaving through interfaces other than tun,
// for every program but Xray itself, whose outbounds (DNS included) use the
// other interfaces on purpose:
//
//   - dns: DNS (port 53) may only go through the TUN. Windows sends a name
//     query to the DNS servers of all interfaces, not only to those of the TUN:
//     to the first server of each interface, then to all of them when no answer
//     arrives within a second or two. It sends the queries for the servers of
//     an interface out through that interface, whatever the routes say, and
//     other programs reach an on-link resolver, like 192.168.1.1 from DHCP,
//     through its LAN route, which is more specific than the TUN's default
//     route. Since Windows 11 and Server 2022, Windows may also send its
//     queries over HTTPS or TLS, so there its DNS Client service may not
//     connect outside the TUN at all, except for name resolution on the local
//     link (mDNS, LLMNR).
//   - ipv4, ipv6: no IPv4, or no IPv6, at all, in either direction, for a TUN
//     that no route of it leads to, except loopback and what Windows itself
//     needs on the local link (DHCP, and for IPv6 neighbor and multicast
//     listener discovery), none of which can leave it. The TUN carries what
//     is routed to it even without an address of that IP version in gateway:
//     Windows gives it link-local ones itself, an IPv6 one at once, an IPv4
//     one from 169.254.0.0/16 after some seconds (until then, IPv4 routed to
//     the TUN is unreachable).
//
// The filters live in a dynamic WFP session: closing the returned engine handle
// with closeWFPEngine deletes them, and so does Windows when the process dies.
func blockLeaks(tun winipcfg.LUID, dns, ipv4, ipv6 bool) (windows.Handle, error) {
	engine, err := openWFPEngine()
	if err != nil {
		return 0, err
	}
	if err := fwpmResult(procFwpmTransactionBegin0.Call(uintptr(engine), 0)); err != nil {
		closeWFPEngine(engine)
		return 0, errors.New("FwpmTransactionBegin0 failed").Base(err)
	}
	err = addLeakFilters(engine, tun, dns, ipv4, ipv6)
	if err == nil {
		if err = fwpmResult(procFwpmTransactionCommit0.Call(uintptr(engine))); err != nil {
			err = errors.New("FwpmTransactionCommit0 failed").Base(err)
		}
	}
	if err != nil {
		procFwpmTransactionAbort0.Call(uintptr(engine))
		closeWFPEngine(engine)
		return 0, err
	}
	return engine, nil
}

func openWFPEngine() (windows.Handle, error) {
	if err := modfwpuclnt.Load(); err != nil {
		return 0, err
	}
	// txnWaitTimeoutInMSec stays 0 for BFE's default, so that a transaction
	// held by another program cannot hang the start forever.
	session := fwpmSession0{
		displayData: fwpmDisplayData0{name: utf16Ptr("Xray TUN")},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine windows.Handle
	if err := fwpmResult(procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine)))); err != nil {
		return 0, errors.New("FwpmEngineOpen0 failed").Base(err)
	}
	return engine, nil
}

func closeWFPEngine(engine windows.Handle) {
	procFwpmEngineClose0.Call(uintptr(engine))
}

// addLeakFilters adds the filters of blockLeaks in a sublayer of their own.
// blockLeaks runs it in a transaction, so that they take effect all at once.
func addLeakFilters(engine windows.Handle, tun winipcfg.LUID, dns, ipv4, ipv6 bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	var appID *fwpByteBlob
	if err := fwpmResult(procFwpmGetAppIdFromFileName0.Call(uintptr(unsafe.Pointer(exePath)), uintptr(unsafe.Pointer(&appID)))); err != nil {
		return errors.New("FwpmGetAppIdFromFileName0 failed for ", exe).Base(err)
	}
	defer func() { procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&appID))) }()

	sublayer := fwpmSublayer0{
		displayData: fwpmDisplayData0{name: utf16Ptr("Xray TUN")},
		weight:      0xffff,
	}
	if sublayer.subLayerKey, err = windows.GenerateGUID(); err != nil {
		return err
	}
	if err := fwpmResult(procFwpmSubLayerAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&sublayer)), 0)); err != nil {
		return errors.New("FwpmSubLayerAdd0 failed").Base(err)
	}
	add := func(layer *windows.GUID, name string, flags, action uint32, weight uint8, conditions ...fwpmFilterCondition0) error {
		return addFilter(engine, &sublayer.subLayerKey, layer, "Xray TUN: "+name, flags, action, weight, conditions...)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	tunLUID := new(uint64)
	*tunLUID = uint64(tun)
	pinner.Pin(tunLUID) // the condition only holds it as uintptr

	// The heaviest matching filter of a sublayer decides. All sublayers have
	// their say, though, and a block in any of them beats a permit, unless
	// the permit is hard: it clears the action right, and then the blocks of
	// lower sublayers, Windows Firewall rules among them, no longer override
	// it, only a callout's veto does. Xray's own connections out get such a
	// hard permit. Connections from outside to Xray get an ordinary one, so
	// that firewalls keep guarding its inbounds.
	self := condition(&fwpmConditionALEAppID, fwpByteBlobType, uintptr(unsafe.Pointer(appID)))
	dns53 := condition(&fwpmConditionIPRemotePort, fwpUint16, 53)
	// DNS goes through the TUN when its local address is the TUN's, and it
	// also leaves, or arrives, through the TUN. The local address alone
	// decides by default, but with weak host sending or receiving enabled,
	// packets of the TUN's address can use other interfaces. (The next hop,
	// the interface replies would leave by, is not known for arriving ones.)
	onTUN := func(field *windows.GUID) fwpmFilterCondition0 {
		return condition(field, fwpUint64, uintptr(unsafe.Pointer(tunLUID)))
	}
	out := []fwpmFilterCondition0{dns53, onTUN(&fwpmConditionIPLocalInterface), onTUN(&fwpmConditionIPNexthopInterface)}
	in := []fwpmFilterCondition0{dns53, onTUN(&fwpmConditionIPLocalInterface), onTUN(&fwpmConditionIPArrivalInterface)}
	for _, layer := range []struct {
		key        *windows.GUID
		selfFlags  uint32
		throughTUN []fwpmFilterCondition0
	}{
		{&fwpmLayerALEAuthConnectV4, fwpmFilterFlagClearActionRight, out},
		{&fwpmLayerALEAuthRecvAcceptV4, 0, in},
		{&fwpmLayerALEAuthConnectV6, fwpmFilterFlagClearActionRight, out},
		{&fwpmLayerALEAuthRecvAcceptV6, 0, in},
	} {
		if err := add(layer.key, "permit Xray", layer.selfFlags, fwpActionPermit, 4, self); err != nil {
			return err
		}
		if dns {
			if err := add(layer.key, "permit DNS through the TUN", 0, fwpActionPermit, 3, layer.throughTUN...); err != nil {
				return err
			}
			if err := add(layer.key, "block DNS", 0, fwpActionBlock, 2, dns53); err != nil {
				return err
			}
		}
	}

	// Since Windows 11 and Server 2022 (build 20348), the DNS Client service
	// may also send the queries for an interface's servers over HTTPS or TLS,
	// out through that interface and to any port. So there it may only
	// connect through the TUN, except for mDNS and LLMNR, which stay on the
	// local link (over an IP version only while it is not blocked altogether).
	// Earlier versions only query port 53, and may run the service in one
	// process with others, which the filters would catch as well. Like
	// Windows Firewall's rules for it, they recognize the service by its SID,
	// which Windows puts in the token of its process: the security descriptor
	// grants that SID the right to match (FWP_ACTRL_MATCH_FILTER, CC in SDDL).
	if _, _, build := windows.RtlGetNtVersionNumbers(); dns && build >= 20348 {
		sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:(A;;CCRC;;;" + dnsClientSID + ")")
		if err != nil {
			return err
		}
		sdBlob := &fwpByteBlob{size: sd.Length(), data: (*byte)(unsafe.Pointer(sd))}
		pinner.Pin(sdBlob) // the condition only holds it as uintptr
		dnsClient := condition(&fwpmConditionALEUserID, fwpSecurityDescriptorType, uintptr(unsafe.Pointer(sdBlob)))
		// Conditions on the same field match when any of them does.
		mdnsLLMNR := []fwpmFilterCondition0{dnsClient, condition(&fwpmConditionIPRemotePort, fwpUint16, 5353), condition(&fwpmConditionIPRemotePort, fwpUint16, 5355)}
		for _, layer := range []struct {
			key       *windows.GUID
			localLink bool
		}{
			{&fwpmLayerALEAuthConnectV4, !ipv4},
			{&fwpmLayerALEAuthConnectV6, !ipv6},
		} {
			if err := add(layer.key, "permit the DNS Client service through the TUN", 0, fwpActionPermit, 3, dnsClient, onTUN(&fwpmConditionIPLocalInterface), onTUN(&fwpmConditionIPNexthopInterface)); err != nil {
				return err
			}
			if layer.localLink {
				if err := add(layer.key, "permit the DNS Client service's mDNS and LLMNR", 0, fwpActionPermit, 3, mdnsLLMNR...); err != nil {
					return err
				}
			}
			if err := add(layer.key, "block the DNS Client service", 0, fwpActionBlock, 2, dnsClient); err != nil {
				return err
			}
		}
	}

	// Both directions: replies to a connection accepted from outside would
	// leave through the physical link as well.
	loopback := fwpmFilterCondition0{
		fieldKey:       fwpmConditionFlags,
		matchType:      fwpMatchFlagsAllSet,
		conditionValue: fwpValue0{typ: fwpUint32, value: fwpConditionFlagIsLoopback},
	}
	if ipv4 {
		// DHCP keeps the addresses of the other interfaces, which Xray's own
		// connections use.
		dhcp := []fwpmFilterCondition0{
			condition(&fwpmConditionIPProtocol, fwpUint8, windows.IPPROTO_UDP),
			condition(&fwpmConditionIPLocalPort, fwpUint16, 68),
			condition(&fwpmConditionIPRemotePort, fwpUint16, 67),
		}
		for _, layer := range []*windows.GUID{&fwpmLayerALEAuthConnectV4, &fwpmLayerALEAuthRecvAcceptV4} {
			if err := add(layer, "permit IPv4 loopback", 0, fwpActionPermit, 1, loopback); err != nil {
				return err
			}
			if err := add(layer, "permit DHCP", 0, fwpActionPermit, 1, dhcp...); err != nil {
				return err
			}
			if err := add(layer, "block IPv4", 0, fwpActionBlock, 0); err != nil {
				return err
			}
		}
	}
	if ipv6 {
		// Neighbor and multicast listener discovery, ICMPv6 130-137 and 143,
		// whose type and code sit where the local and remote port are.
		discovery := []fwpmFilterCondition0{condition(&fwpmConditionIPProtocol, fwpUint8, windows.IPPROTO_ICMPV6)}
		for _, typ := range []uintptr{130, 131, 132, 133, 134, 135, 136, 137, 143} {
			discovery = append(discovery, condition(&fwpmConditionIPLocalPort, fwpUint16, typ))
		}
		discovery = append(discovery, condition(&fwpmConditionIPRemotePort, fwpUint16, 0))
		dhcpv6 := []fwpmFilterCondition0{
			condition(&fwpmConditionIPProtocol, fwpUint8, windows.IPPROTO_UDP),
			condition(&fwpmConditionIPLocalPort, fwpUint16, 546),
			condition(&fwpmConditionIPRemotePort, fwpUint16, 547),
		}
		for _, direction := range []struct {
			layer  *windows.GUID
			dhcpv6 []fwpmFilterCondition0
		}{
			// The client sends to the servers' multicast address, and they
			// answer from their own.
			{&fwpmLayerALEAuthConnectV6, slices.Concat(dhcpv6, []fwpmFilterCondition0{condition(&fwpmConditionIPRemoteAddress, fwpByteArray16Type, uintptr(unsafe.Pointer(&ipv6AllDHCPv6Servers)))})},
			{&fwpmLayerALEAuthRecvAcceptV6, dhcpv6},
		} {
			if err := add(direction.layer, "permit IPv6 loopback", 0, fwpActionPermit, 1, loopback); err != nil {
				return err
			}
			if err := add(direction.layer, "permit IPv6 neighbor and multicast listener discovery", 0, fwpActionPermit, 1, discovery...); err != nil {
				return err
			}
			if err := add(direction.layer, "permit DHCPv6", 0, fwpActionPermit, 1, direction.dhcpv6...); err != nil {
				return err
			}
			if err := add(direction.layer, "block IPv6", 0, fwpActionBlock, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func addFilter(engine windows.Handle, sublayer, layer *windows.GUID, name string, flags, action uint32, weight uint8, conditions ...fwpmFilterCondition0) error {
	filter := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: utf16Ptr(name)},
		flags:               flags,
		layerKey:            *layer,
		subLayerKey:         *sublayer,
		weight:              fwpValue0{typ: fwpUint8, value: uintptr(weight)},
		numFilterConditions: uint32(len(conditions)),
		action:              fwpmAction0{typ: action},
	}
	if len(conditions) > 0 {
		filter.filterCondition = &conditions[0]
	}
	if err := fwpmResult(procFwpmFilterAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&filter)), 0, 0)); err != nil {
		return errors.New("FwpmFilterAdd0 failed for ", name).Base(err)
	}
	return nil
}

// dnsOutsideTUN returns the servers outside all of prefixes, the TUN's own
// subnets and routes: queries to them cannot go through the TUN.
func dnsOutsideTUN(servers []netip.Addr, prefixes []netip.Prefix) []netip.Addr {
	var outside []netip.Addr
	for _, server := range servers {
		server = server.Unmap()
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(server) }) {
			outside = append(outside, server)
		}
	}
	return outside
}

// flushDNSCache drops the answers Windows cached so far, like ipconfig
// /flushdns, so that names get resolved again with the current DNS setup.
func flushDNSCache() error {
	if err := procDnsFlushResolverCache.Find(); err != nil {
		return err
	}
	if r, _, err := procDnsFlushResolverCache.Call(); r == 0 {
		return err
	}
	return nil
}
