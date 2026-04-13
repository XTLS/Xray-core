//go:build windows

package tun

import (
	"crypto/md5"
	"encoding/binary"
	go_errors "errors"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
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

	options        *Config
	adapter        *wintun.Adapter
	session        wintun.Session
	readWait       windows.Handle
	luid           winipcfg.LUID
	changeCallback winipcfg.ChangeCallback
	closed         bool
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

func (t *WindowsTun) Start() error {
	var has4, has6 bool
	allowedIPs := make([]netip.Prefix, 0, len(t.options.AutoSystemRoutingTable))
	for _, route := range t.options.AutoSystemRoutingTable {
		allowedIPs = append(allowedIPs, netip.MustParsePrefix(route))
	}
	routesMap := make(map[winipcfg.RouteData]struct{})
	for _, ip := range allowedIPs {
		route := winipcfg.RouteData{
			Destination: ip.Masked(),
			Metric:      0,
		}
		if ip.Addr().Is4() {
			has4 = true
			route.NextHop = netip.IPv4Unspecified()
		} else {
			has6 = true
			route.NextHop = netip.IPv6Unspecified()
		}
		routesMap[route] = struct{}{}
	}
	routesData := make([]*winipcfg.RouteData, 0, len(routesMap))
	for route := range routesMap {
		r := route
		routesData = append(routesData, &r)
	}
	err := t.luid.SetRoutes(routesData)
	if err != nil {
		return errors.New("unable to set routes").Base(err)
	}

	if len(t.options.Gateway) > 0 {
		addresses := make([]netip.Prefix, 0, len(t.options.Gateway))
		for _, address := range t.options.Gateway {
			addresses = append(addresses, netip.MustParsePrefix(address))
		}
		err := t.luid.SetIPAddresses(addresses)
		if err != nil {
			return errors.New("unable to set ips").Base(err)
		}
	}

	if has4 {
		ipif, err := t.luid.IPInterface(windows.AF_INET)
		if err != nil {
			return err
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = t.options.MTU[0]
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		err = ipif.Set()
		if err != nil {
			return err
		}
	}
	if has6 {
		ipif, err := t.luid.IPInterface(windows.AF_INET6)
		if err != nil {
			return err
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = t.options.MTU[1]
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		err = ipif.Set()
		if err != nil {
			return err
		}
	}

	if len(t.options.DNS) > 0 {
		dns := make([]netip.Addr, 0, len(t.options.DNS))
		for _, ip := range t.options.DNS {
			dns = append(dns, netip.MustParseAddr(ip))
		}
		err := t.luid.SetDNS(windows.AF_INET, dns, nil)
		if err != nil {
			return err
		}
		err = t.luid.SetDNS(windows.AF_INET6, dns, nil)
		if err != nil {
			return err
		}
	}

	if updater != nil {
		t.changeCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
			if notificationType != winipcfg.MibDeleteInstance {
				return
			}
			updater.Update()
		})
		if err != nil {
			return err
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

	if t.changeCallback != nil {
		t.changeCallback.Unregister()
	}
	t.session.End()
	_ = t.adapter.Close()

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
	return &LinkEndpoint{deviceMTU: t.options.MTU[0], device: t}, nil
}

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(iface.Index))

	switch network {
	case "tcp4", "udp4", "ip4":
		err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_UNICAST_IF, *(*int)(unsafe.Pointer(&index[0])))
		if err != nil {
			return err
		}
		if network == "udp4" {
			return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MULTICAST_IF, *(*int)(unsafe.Pointer(&index[0])))
		}
	case "tcp6", "udp6", "ip6":
		err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_UNICAST_IF, iface.Index)
		if err != nil {
			return err
		}
		if network == "udp6" {
			return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_MULTICAST_IF, iface.Index)
		}
	default:
		return errors.New("unknown network ", network)
	}

	return nil
}
