//go:build windows

package tun

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	go_errors "errors"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/tun/firewall"
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
	adapter, err := open(options.Name)
	if err != nil {
		return nil, err
	}

	// start the interface with ring buffer capacity of 8 MiB
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}

	err = firewall.EnableFirewall(adapter.LUID())
	if err != nil {
		session.End()
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

func open(name string) (*wintun.Adapter, error) {
	// generate a deterministic GUID from the adapter name
	id := md5.Sum([]byte(name))
	guid := (*windows.GUID)(unsafe.Pointer(&id[0]))
	// try to create adapter anew
	adapter, err := wintun.CreateAdapter(name, "Xray", guid)
	if err == nil {
		return adapter, nil
	}
	return nil, err
}

func (t *WindowsTun) Start() (err error) {
	if updater != nil {
		t.cbr, err = winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
			updater.Update()
		})
		if err != nil {
			return err
		}
		t.cbi, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
			updater.Update()
		})
		if err != nil {
			return err
		}
	}

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
	var dns4, dns6 bool
	dns := make([]netip.Addr, 0, len(t.options.DNS))
	for _, ip := range t.options.DNS {
		addr := netip.MustParseAddr(ip)
		if addr.Is4() {
			dns4 = true
		} else {
			dns6 = true
		}
		dns = append(dns, addr)
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
	var lastErr error
startOver:
	if retryTimes > 0 {
		if retryTimes > 15 {
			return windows.ERROR_NOT_FOUND
		}
		errors.LogErrorInner(context.Background(), lastErr, "Interface configuration failed, retrying attempt ", retryTimes, "/15")
		time.Sleep(time.Second)
	}
	retryTimes++
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if family == windows.AF_INET && route4 || family == windows.AF_INET6 && route6 {
			err = t.luid.SetRoutesForFamily(family, routesData)
			if err != nil {
				lastErr = errors.New("unable to set routes").Base(err)
				if err == windows.ERROR_NOT_FOUND {
					goto startOver
				}
				return lastErr
			}
		}
		if family == windows.AF_INET && address4 || family == windows.AF_INET6 && address6 {
			err = t.luid.SetIPAddressesForFamily(family, addresses)
			if err != nil {
				lastErr = errors.New("unable to set ips").Base(err)
				if err == windows.ERROR_NOT_FOUND {
					goto startOver
				}
				return lastErr
			}
		}
		ipif, err := t.luid.IPInterface(family)
		if err != nil {
			return err
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = t.options.MTU
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		err = ipif.Set()
		if err != nil {
			lastErr = errors.New("unable to set metric and MTU").Base(err)
			if err == windows.ERROR_NOT_FOUND {
				goto startOver
			}
			return lastErr
		}
		if family == windows.AF_INET && dns4 || family == windows.AF_INET6 && dns6 {
			err = t.luid.SetDNS(family, dns, nil)
			if err != nil {
				lastErr = errors.New("unable to set DNS").Base(err)
				if err == windows.ERROR_NOT_FOUND {
					goto startOver
				}
				return lastErr
			}
		}
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

	firewall.DisableFirewall()
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
	if t.session != (wintun.Session{}) {
		t.session.End()
	}
	if t.adapter != nil {
		t.adapter.Close()
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
