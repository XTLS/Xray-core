//go:build windows

package tun

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	go_errors "errors"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

// WindowsTun is an object that handles tun network interface on Windows
// current version is heavily stripped to do nothing more,
// then create a network interface, to be provided as endpoint to gVisor ip stack
type WindowsTun struct {
	sync.RWMutex

	options  *Config
	adapter  *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle
	luid     winipcfg.LUID
	cbr      winipcfg.ChangeCallback
	cbi      winipcfg.ChangeCallback
	wfp      windows.Handle
	resolver *savedResolver
	skipStop chan struct{}
	skipDone chan struct{}
	closed   bool
}

// WindowsTun implements Tun
var _ Tun = (*WindowsTun)(nil)

// WindowsTun implements GVisorDevice
var _ GVisorDevice = (*WindowsTun)(nil)

// NewTun creates a Wintun interface with the given name. Should a Wintun
// interface with the same name exist, it tried to be reused.
func NewTun(options *Config) (Tun, error) {
	// instantiate wintun adapter
	adapter, err := open(options.Name, options.Desc)
	if err != nil {
		return nil, err
	}

	// start the interface with ring buffer capacity of 8 MiB
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}

	tun := &WindowsTun{
		options:  options,
		adapter:  adapter,
		session:  session,
		readWait: session.ReadWaitEvent(),
		luid:     winipcfg.LUID(adapter.LUID()),
	}

	return tun, nil
}

func open(name, desc string) (*wintun.Adapter, error) {
	// generate a deterministic GUID from the adapter name
	id := md5.Sum([]byte(name))
	guid := (*windows.GUID)(unsafe.Pointer(&id[0]))
	// try to open existing adapter by name
	adapter, err := wintun.OpenAdapter(name)
	if err == nil {
		return adapter, nil
	}
	// try to create adapter anew
	adapter, err = wintun.CreateAdapter(name, desc, guid)
	if err == nil {
		return adapter, nil
	}
	return nil, err
}

func (t *WindowsTun) Start() (err error) {
	var address4, address6 bool
	addresses := make([]netip.Prefix, 0, len(t.options.Gateway))
	for _, cidr := range t.options.Gateway {
		prefix := netip.MustParsePrefix(cidr)
		if prefix.Addr().Is4() {
			address4 = true
		} else {
			address6 = true
		}
		addresses = append(addresses, prefix)
	}

	dns := make([]netip.Addr, 0, len(t.options.DNS))
	for _, ip := range t.options.DNS {
		dns = append(dns, netip.MustParseAddr(ip))
	}

	var route4, route6 bool
	routesMap := make(map[winipcfg.RouteData]struct{})
	for _, cidr := range t.options.AutoSystemRoutingTable {
		prefix := netip.MustParsePrefix(cidr)
		route := winipcfg.RouteData{
			Destination: prefix.Masked(),
			Metric:      0,
		}
		if prefix.Addr().Is4() {
			route4 = true
			route.NextHop = netip.IPv4Unspecified()
		} else {
			route6 = true
			route.NextHop = netip.IPv6Unspecified()
		}
		routesMap[route] = struct{}{}
	}
	routesData := make([]*winipcfg.RouteData, 0, len(routesMap))
	for route := range routesMap {
		r := route
		routesData = append(routesData, &r)
	}

	var retryTimes int
	var firstErr error
startOver:
	if retryTimes > 0 {
		if retryTimes > 15 {
			return windows.ERROR_NOT_FOUND
		}
		errors.LogErrorInner(context.Background(), firstErr, "Interface configuration failed, retrying attempt ", retryTimes, "/15")
		time.Sleep(time.Second)
	}
	retryTimes++
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if family == windows.AF_INET && route4 || family == windows.AF_INET6 && route6 {
			err = t.luid.SetRoutesForFamily(family, routesData)
			if err != nil {
				firstErr = errors.New("unable to set routes").Base(err)
				if err == windows.ERROR_NOT_FOUND {
					goto startOver
				}
				return firstErr
			}
		}
		if family == windows.AF_INET && address4 || family == windows.AF_INET6 && address6 {
			err = t.luid.SetIPAddressesForFamily(family, addresses)
			if err != nil {
				firstErr = errors.New("unable to set ips").Base(err)
				if err == windows.ERROR_NOT_FOUND {
					goto startOver
				}
				return firstErr
			}
		}
		ipif, err := t.luid.IPInterface(family)
		if err != nil {
			// With IPv6 disabled system-wide (DisabledComponents), the adapter has no
			// IPv6 interface at all. Skip the family unless the config asks for it.
			if err == windows.ERROR_NOT_FOUND && family == windows.AF_INET6 && !address6 && !route6 {
				continue
			}
			return err
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		if family == windows.AF_INET && (address4 || route4) || family == windows.AF_INET6 && (address6 || route6) {
			ipif.NLMTU = t.options.MTU
		}
		if family == windows.AF_INET && route4 || family == windows.AF_INET6 && route6 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		err = ipif.Set()
		if err != nil {
			firstErr = errors.New("unable to set metric and MTU").Base(err)
			if err == windows.ERROR_NOT_FOUND {
				goto startOver
			}
			return firstErr
		}
		err = t.luid.SetDNS(family, dns, nil)
		if err != nil {
			firstErr = errors.New("unable to set DNS").Base(err)
			if err == windows.ERROR_NOT_FOUND {
				goto startOver
			}
			return firstErr
		}
	}

	// Windows lists the TUN's DNS servers among the system's ones, which Go's
	// resolver queries for Xray's own lookups past the TUN, where they lead
	// nowhere or back into Xray. Not skipped are those another interface uses
	// as well, as that could leave no server at all. As those can change at
	// any time, they are looked at again as often as Go rereads its servers.
	if len(dns) > 0 {
		skipped, err := tunOnlyDNS(t.luid, dns)
		if err != nil {
			skipped = dns
		}
		internet.SkipDNSServers(skipped)
		t.skipStop, t.skipDone = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(t.skipDone)
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if skipped, err := tunOnlyDNS(t.luid, dns); err == nil {
						internet.SkipDNSServers(skipped)
					}
				case <-t.skipStop:
					return
				}
			}
		}()
	}

	// Keep Windows from registering the TUN's addresses, and the host name
	// with them, through dynamic DNS updates. Best effort.
	if address4 || address6 {
		if err := disableDNSRegistration(t.luid, dns); err != nil {
			errors.LogDebugInner(context.Background(), err, "[tun] unable to disable DNS registration")
		}
	}

	// With autoSystemWfpBlockLeak, once the system routes lead to the TUN,
	// keep DNS ("dns", if dns is set), and an IP version no route of which
	// leads to the TUN ("misconfigtun"), from leaving through the other
	// interfaces. Addresses do not matter: without one of a version in
	// gateway, Windows gives the TUN a link-local one.
	leaks := t.options.AutoSystemWfpBlockLeak
	blockDNS := slices.Contains(leaks, "dns") && len(dns) > 0
	blockIPv4 := slices.Contains(leaks, "misconfigtun") && !route4
	blockIPv6 := slices.Contains(leaks, "misconfigtun") && !route6
	if (route4 || route6) && (blockDNS || blockIPv4 || blockIPv6) {
		if t.wfp, err = blockLeaks(t.luid, blockDNS, blockIPv4, blockIPv6); err != nil {
			var blocked []string
			for _, b := range []struct {
				on   bool
				what string
			}{{blockDNS, "DNS"}, {blockIPv4, "IPv4"}, {blockIPv6, "IPv6"}} {
				if b.on {
					blocked = append(blocked, b.what)
				}
			}
			// Rather no TUN than a leaking one.
			return errors.New("unable to block ", strings.Join(blocked, " and "), " outside the TUN (remove autoSystemWfpBlockLeak to run without)").Base(err)
		}
		errors.LogInfo(context.Background(), "[tun] outside the TUN, blocked DNS: ", blockDNS, ", blocked IPv4: ", blockIPv4, ", blocked IPv6: ", blockIPv6)
		if blockDNS {
			covered := slices.Clone(addresses)
			for _, route := range routesData {
				covered = append(covered, route.Destination)
			}
			for _, server := range dnsOutsideTUN(dns, covered) {
				errors.LogWarning(context.Background(), "[tun] DNS server ", server, " is in neither gateway nor autoSystemRoutingTable, so queries to it cannot go through the TUN and are blocked")
			}
			// With updater, the dialer controllers bind Xray's own sockets
			// to the physical interface.
			if updater != nil {
				t.resolver = resolveOnOwn()
			}
		}
	}
	if len(dns) > 0 || route4 || route6 {
		if err := flushDNSCache(); err != nil {
			errors.LogInfoInner(context.Background(), err, "[tun] unable to flush DNS cache")
		}
	}

	if updater != nil {
		// Only a registered callback goes into the fields: a nil pointer in
		// them would not compare equal to nil in Close.
		cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
			updater.Update()
		})
		if err != nil {
			return err
		}
		t.cbr = cbr
		cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
			updater.Update()
		})
		if err != nil {
			return err
		}
		t.cbi = cbi
	}
	return nil
}

func (t *WindowsTun) Close() error {
	t.Lock()
	defer t.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	if t.cbr != nil {
		t.cbr.Unregister()
	}
	if t.cbi != nil {
		t.cbi.Unregister()
	}
	if t.luid != 0 {
		t.luid.FlushRoutes(windows.AF_INET)
		t.luid.FlushIPAddresses(windows.AF_INET)
		t.luid.FlushDNS(windows.AF_INET)
		t.luid.FlushRoutes(windows.AF_INET6)
		t.luid.FlushIPAddresses(windows.AF_INET6)
		t.luid.FlushDNS(windows.AF_INET6)
	}
	if t.wfp != 0 {
		closeWFPEngine(t.wfp)
	}
	if t.resolver != nil {
		t.resolver.restore()
	}
	if t.skipStop != nil {
		close(t.skipStop)
		<-t.skipDone
	}
	internet.SkipDNSServers(nil)
	if len(t.options.DNS) > 0 || len(t.options.AutoSystemRoutingTable) > 0 {
		flushDNSCache()
	}
	if t.session != (wintun.Session{}) {
		t.session.End()
	}
	if t.adapter != nil {
		t.adapter.Close()
	}
	return nil
}

type savedResolver struct {
	preferGo bool
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
}

// resolveOnOwn has Go resolve the names Xray would otherwise ask Windows for,
// on Xray's own sockets, which the dialer controllers bind to the physical
// interface, and skipping the TUN's DNS servers, as localdns does. Windows'
// resolver runs in the DNS Client service, whose queries the DNS filter lets
// through the TUN only, so Xray's own lookups, like of an outbound's server
// domain, would go into Xray again and could end up waiting on themselves.
//
// It changes net.DefaultResolver for the whole process, which covers every
// lookup that would reach Windows' resolver; restore undoes it.
func resolveOnOwn() *savedResolver {
	saved := &savedResolver{net.DefaultResolver.PreferGo, net.DefaultResolver.Dial}
	dialer := &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		for _, ctl := range internet.Controllers {
			if err := ctl(network, address, c); err != nil {
				return err
			}
		}
		return nil
	}}
	// Go's resolver moves on to the next server right away when a dial fails.
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if internet.IsSkippedDNSServer(address) {
			return nil, errors.New("skipped DNS server ", address)
		}
		return dialer.DialContext(ctx, network, address)
	}
	net.DefaultResolver.PreferGo = true
	return saved
}

func (s *savedResolver) restore() {
	net.DefaultResolver.PreferGo = s.preferGo
	net.DefaultResolver.Dial = s.dial
}

// tunOnlyDNS returns those of servers, the TUN's DNS servers, that Go's
// resolver does not also get from another interface: one that is up and has
// a gateway, as it reads them.
func tunOnlyDNS(tun winipcfg.LUID, servers []netip.Addr) ([]netip.Addr, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return nil, err
	}
	var others []netip.Addr
	for _, adapter := range adapters {
		if adapter.LUID == tun || adapter.OperStatus != winipcfg.IfOperStatusUp || adapter.FirstGatewayAddress == nil {
			continue
		}
		for server := adapter.FirstDNSServerAddress; server != nil; server = server.Next {
			if addr, ok := netip.AddrFromSlice(server.Address.IP()); ok {
				others = append(others, addr.Unmap())
			}
		}
	}
	return slices.DeleteFunc(slices.Clone(servers), func(server netip.Addr) bool {
		return slices.Contains(others, server.Unmap())
	}), nil
}

// disableDNSRegistration turns off the dynamic DNS registration of the
// interface's addresses. dns are its DNS servers.
func disableDNSRegistration(luid winipcfg.LUID, dns []netip.Addr) error {
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	err = winipcfg.SetInterfaceDnsSettings(*guid, &winipcfg.DnsInterfaceSettings{
		Version: winipcfg.DnsInterfaceSettingsVersion1,
		Flags:   winipcfg.DnsInterfaceSettingsFlagRegistrationEnabled,
	})
	if err == nil || !go_errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return err
	}
	return disableDNSRegistrationByNetsh(luid, dns)
}

// disableDNSRegistrationByNetsh does it for Windows before 10 1809, which
// lacks SetInterfaceDnsSettings. The setting is the interface's, not the
// address family's, but netsh only applies it along with a DNS server, which
// replaces the IPv4 ones, so they are set again afterwards.
func disableDNSRegistrationByNetsh(luid winipcfg.LUID, dns []netip.Addr) error {
	row, err := luid.Interface()
	if err != nil {
		return err
	}
	server := "127.0.0.1" // any will do when there is no IPv4 one
	if i := slices.IndexFunc(dns, netip.Addr.Is4); i >= 0 {
		server = dns[i].String()
	}
	err = runNetsh("interface", "ipv4", "set", "dnsservers", "name="+strconv.FormatUint(uint64(row.InterfaceIndex), 10), "source=static", "address="+server, "register=none", "validate=no")
	return errors.Combine(err, luid.SetDNS(windows.AF_INET, dns, nil))
}

// runNetsh runs netsh.exe from the system directory. netsh reports some
// failures, like a syntax error, only in its output, even with exit code 0,
// so any output counts as a failure.
func runNetsh(args ...string) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(system32, "netsh.exe"), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if output = bytes.TrimSpace(output); err != nil || len(output) > 0 {
		return errors.New("netsh ", strings.Join(args, " "), ": ", string(output)).Base(err)
	}
	return nil
}

func (t *WindowsTun) Name() (string, error) {
	row, err := t.luid.Interface()
	if err != nil {
		return "", err
	}
	return row.Alias(), nil
}

func (t *WindowsTun) Index() (int, error) {
	row, err := t.luid.Interface()
	if err != nil {
		return 0, err
	}
	return int(row.InterfaceIndex), nil
}

// WritePacket implements GVisorDevice method to write one packet to the tun device
func (t *WindowsTun) WritePacket(packetBuffer *stack.PacketBuffer) tcpip.Error {
	t.RLock()
	defer t.RUnlock()
	if t.closed {
		return &tcpip.ErrClosedForSend{}
	}

	// request buffer from Wintun
	packet, err := t.session.AllocateSendPacket(packetBuffer.Size())
	if err != nil {
		return &tcpip.ErrAborted{}
	}

	// copy the bytes of slices that compose the packet into the allocated buffer
	var index int
	for _, packetElement := range packetBuffer.AsSlices() {
		index += copy(packet[index:], packetElement)
	}

	// signal Wintun to send that buffer as the packet
	t.session.SendPacket(packet)

	return nil
}

// ReadPacket implements GVisorDevice method to read one packet from the tun device
// It is expected that the method will not block, rather return ErrQueueEmpty when there is nothing on the line,
// which will make the stack call Wait which should implement desired push-back
func (t *WindowsTun) ReadPacket() (byte, *stack.PacketBuffer, error) {
	packet, err := t.session.ReceivePacket()
	if go_errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		return 0, nil, ErrQueueEmpty
	}
	if err != nil {
		return 0, nil, err
	}

	version := packet[0] >> 4
	packetBuffer := buffer.MakeWithView(buffer.NewViewWithData(packet))
	return version, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			t.session.ReleaseReceivePacket(packet)
		},
	}), nil
}

func (t *WindowsTun) Wait() {
	procyield(1)
	_, _ = windows.WaitForSingleObject(t.readWait, windows.INFINITE)
}

func (t *WindowsTun) newEndpoint() (stack.LinkEndpoint, error) {
	return &LinkEndpoint{deviceMTU: t.options.MTU, device: t}, nil
}

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(iface.Index))

	var err1, err2, err3, err4 error

	switch network {
	case "tcp6", "udp6", "ip6":
		err1 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_UNICAST_IF, iface.Index)
		if network == "udp6" {
			err2 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_MULTICAST_IF, iface.Index)
		}
		fallthrough
	case "tcp4", "udp4", "ip4":
		err3 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_UNICAST_IF, *(*int)(unsafe.Pointer(&index[0])))
		if network == "udp4" || network == "udp6" {
			err4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MULTICAST_IF, *(*int)(unsafe.Pointer(&index[0])))
		}
	default:
		panic(network + " " + address)
	}

	return errors.Combine(err1, err2, err3, err4)
}

func findOutboundInterface(tunIndex int, fixedName string) (*net.Interface, error) {
	if fixedName != "" {
		return net.InterfaceByName(fixedName)
	}

	r, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0)
	lowestMetricWifi := ^uint32(0)
	indexWifi := uint32(0)
	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceIndex == uint32(tunIndex) {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		iface, err := r[i].InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			iface, err = r[i].InterfaceLUID.IPInterface(windows.AF_INET6)
			if err != nil {
				continue
			}
		}

		if ifrow.Type == windows.IF_TYPE_IEEE80211 {
			if r[i].Metric+iface.Metric < lowestMetricWifi {
				lowestMetricWifi = r[i].Metric + iface.Metric
				indexWifi = r[i].InterfaceIndex
			}
			continue
		}
		if r[i].Metric+iface.Metric < lowestMetric {
			lowestMetric = r[i].Metric + iface.Metric
			index = r[i].InterfaceIndex
		}
	}
	if indexWifi != 0 {
		index = indexWifi
	}
	return net.InterfaceByIndex(int(index))
}
