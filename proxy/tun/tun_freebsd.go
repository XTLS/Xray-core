//go:build freebsd

package tun

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/buf"
	xerrors "github.com/xtls/xray-core/common/errors"
)

const (
	tunHeaderSize         = 4
	defaultFreeBSDGateway = "169.254.10.1/30"

	// escapeFib is the routing table outbound sockets are switched to so
	// their traffic bypasses the TUN routes installed in the default FIB
	// (FreeBSD's substitute for the per-socket interface binding other
	// platforms use). Requires the boot tunable net.fibs >= 2.
	escapeFib = 1
)

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

type FreeBSDTun struct {
	device        tun.Device
	options       *Config
	name          string
	tunIndex      int
	autoInterface bool
	// local is the address the system itself has on the TUN; gateway is the
	// address before it, which nothing owns, so a packet to it is routed into
	// the TUN (see selectFreeBSDGateway).
	gateway netip.Prefix
	local   netip.Addr

	systemDNSSet   bool
	systemDNSDirty bool

	systemRoutes     []netip.Prefix
	escapeMu         sync.Mutex
	escapeRoutes     []escapeRoute
	routeMonitor     *os.File
	routeMonitorOnce sync.Once
}

// escapeRoute remembers one route written into the escape FIB, in the exact
// shape needed to delete it again. A zero gateway means an interface route.
type escapeRoute struct {
	prefix  netip.Prefix
	ifIndex int
	gateway netip.Addr
}

var (
	_ Tun          = (*FreeBSDTun)(nil)
	_ GVisorDevice = (*FreeBSDTun)(nil)
)

// NewTun builds new tun interface handler
func NewTun(options *Config) (Tun, error) {
	gateway, local, err := selectFreeBSDGateway(options.Gateway)
	if err != nil {
		return nil, err
	}

	// net.fibs is a boot-time constant, so validate the escape routing table
	// before the shared handler registers a dialer controller that would
	// otherwise steer every outbound socket into a table that was never set up.
	if options.AutoOutboundsInterface != "" {
		if err := checkEscapeFib(); err != nil {
			return nil, err
		}
	}

	tunDev, err := tun.CreateTUN(options.Name, int(options.MTU))
	if err != nil {
		return nil, err
	}

	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, err
	}
	// From here the interface exists in the kernel; the wireguard library does
	// not remove it on Close, so every failure path must destroy it too or the
	// next start fails with "interface already exists".
	iface, err := net.InterfaceByName(name)
	if err != nil {
		_ = tunDev.Close()
		destroyInterface(name)
		return nil, err
	}
	if err := setIPAddress(name, gateway, local, iface.Index); err != nil {
		_ = tunDev.Close()
		destroyInterface(name)
		return nil, err
	}

	return &FreeBSDTun{
		device:        tunDev,
		options:       options,
		name:          name,
		tunIndex:      iface.Index,
		autoInterface: options.AutoOutboundsInterface != "",
		gateway:       gateway,
		local:         local,
	}, nil
}

// selectFreeBSDGateway picks the first IPv4 prefix from the configured gateway
// list and the local address derived from it (the darwin semantics: the
// interface gets the address right after the gateway, and the gateway, which
// nothing owns, is routed into the TUN), falling back to the same link-local
// default.
func selectFreeBSDGateway(configured []string) (netip.Prefix, netip.Addr, error) {
	gateway := netip.MustParsePrefix(defaultFreeBSDGateway)
	if len(configured) > 0 {
		found := false
		for _, value := range configured {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return netip.Prefix{}, netip.Addr{}, xerrors.New("invalid FreeBSD gateway ", value).Base(err)
			}
			if prefix.Addr().Is4() {
				gateway, found = prefix, true
				break
			}
		}
		if !found {
			return netip.Prefix{}, netip.Addr{}, xerrors.New("FreeBSD gateway requires at least one IPv4 prefix")
		}
	}

	local, ok := nextLocalIPv4(gateway)
	if !ok || !gateway.Contains(local) {
		return netip.Prefix{}, netip.Addr{}, xerrors.New("FreeBSD gateway ", gateway.String(), " must contain at least one usable local IPv4 address after the gateway address")
	}
	return gateway, local, nil
}

func nextLocalIPv4(gateway netip.Prefix) (netip.Addr, bool) {
	local4 := gateway.Addr().As4()
	for i := len(local4) - 1; i >= 0; i-- {
		local4[i]++
		if local4[i] != 0 {
			return netip.AddrFrom4(local4), true
		}
	}
	return netip.Addr{}, false
}

func (t *FreeBSDTun) Start() error {
	if err := t.setSystemRoutes(); err != nil {
		return err
	}

	// Gate on this instance's own option, not the package-global updater,
	// which a previously-removed inbound may have left set. checkEscapeFib
	// already ran in NewTun, before the dialer controller was registered.
	if t.autoInterface {
		if err := t.syncEscapeFib(); err != nil {
			_ = t.unsetSystemRoutes()
			return err
		}
		fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
		if err != nil {
			t.unsetEscapeFib()
			_ = t.unsetSystemRoutes()
			return err
		}
		t.routeMonitor = os.NewFile(uintptr(fd), "xray-route-monitor")
		go t.monitorRouteChanges()
	}
	return nil
}

// monitorRouteChanges refreshes the outbound interface and the escape FIB
// mirror whenever the system routing table changes.
func (t *FreeBSDTun) monitorRouteChanges() {
	buffer := make([]byte, 64*1024)
	for {
		if _, err := t.routeMonitor.Read(buffer); err != nil {
			if !errors.Is(err, os.ErrClosed) {
				xerrors.LogInfoInner(context.Background(), err, "[tun] failed to monitor route changes")
			}
			return
		}
		if updater != nil {
			updater.Update()
		}
		if err := t.syncEscapeFib(); err != nil {
			xerrors.LogInfoInner(context.Background(), err, "[tun] failed to refresh escape routes")
		}
	}
}

func (t *FreeBSDTun) Close() error {
	t.routeMonitorOnce.Do(func() {
		if t.routeMonitor != nil {
			_ = t.routeMonitor.Close()
		}
	})
	t.unsetSystemDNS()
	t.unsetEscapeFib()
	routeErr := t.unsetSystemRoutes()
	name, nameErr := t.Name()
	closeErr := t.device.Close()
	// The wireguard tun device does not tear the interface down on FreeBSD,
	// so an unclean shutdown would leave utun<n> behind and the next start
	// would fail with "interface already exists"; destroy it explicitly.
	if nameErr == nil {
		destroyInterface(name)
	}
	return xerrors.Combine(routeErr, closeErr)
}

// resolvconfRunner runs resolvconf(8) with the given stdin. Overridable for
// tests.
var resolvconfRunner = func(stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command("resolvconf", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// readResolverFile reads one of the files the applied check looks at.
// Overridable for tests.
var readResolverFile = os.ReadFile

// resolvconfApplied reports whether the nameserver resolvconf was handed
// reached a resolver. resolvconf exits 0 with resolvconf=NO in
// resolvconf.conf, and still records the entry for the interface, but runs no
// subscriber, so the exit status and `resolvconf -l` prove nothing; what the
// subscribers wrote does. The libc subscriber writes /etc/resolv.conf, where
// the nameserver also has to be the exclusive one. With
// local_unbound, local-unbound-setup turns that subscriber off and names
// unbound's forwarders file as unbound_conf instead, with resolv.conf left
// pointed at loopback, so that file is checked next.
func resolvconfApplied(addr netip.Addr) (bool, error) {
	resolvConf, err := readResolverFile("/etc/resolv.conf")
	if err != nil {
		return false, err
	}
	if exclusiveNameserver(resolvConf, addr) {
		return true, nil
	}
	resolvconfConf, err := readResolverFile("/etc/resolvconf.conf")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if path := shellAssignment(resolvconfConf, "unbound_conf"); path != "" {
		forwarders, err := readResolverFile(path)
		if err != nil {
			return false, err
		}
		if hasDirective(forwarders, "forward-addr:", addr) {
			return true, nil
		}
	}
	return false, nil
}

// exclusiveNameserver reports whether resolv.conf lists addr as a nameserver
// and no other one except on loopback. With inclusive_interfaces in
// resolvconf.conf the exclusive marking of -x is ignored and the nameservers
// DHCP supplied stay listed, and the system falls back to them: that is the
// leak the takeover exists to close, so it does not count as applied. A
// loopback nameserver alongside is a local resolver that resolvconf feeds.
func exclusiveNameserver(resolvConf []byte, addr netip.Addr) bool {
	found := false
	for _, line := range strings.Split(string(resolvConf), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		if fields[1] == addr.String() {
			found = true
			continue
		}
		if other, err := netip.ParseAddr(fields[1]); err != nil || !other.IsLoopback() {
			return false
		}
	}
	return found
}

// hasDirective reports whether a line of content is the keyword followed by
// the address, as in `forward-addr: 10.0.0.1`.
func hasDirective(content []byte, keyword string, addr netip.Addr) bool {
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == keyword && fields[1] == addr.String() {
			return true
		}
	}
	return false
}

// shellAssignment returns the value of `name=value` in a sh-style config such
// as resolvconf.conf, without surrounding quotes, or empty when it is not set.
func shellAssignment(content []byte, name string) string {
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		value, ok := strings.CutPrefix(line, name+"=")
		if !ok {
			continue
		}
		return strings.Trim(value, `"'`)
	}
	return ""
}

// ConfigureSystemDNS hands the TUN's gateway address to resolvconf(8) as the
// exclusive nameserver, so name lookups resolve through Xray instead of
// leaking to the physical link.
//
// It acts only when the config opts in, and it verifies the data path first:
// unless a query to the gateway would actually be handled, host-wide
// resolution is left to the OS and an error returned. The caller does not
// start the TUN on an error, as the system DNS would bypass it.
func (t *FreeBSDTun) ConfigureSystemDNS(ctx context.Context, inboundTag string) error {
	if !t.options.AutoSystemDnsToGateway {
		return nil
	}
	if t.systemDNSSet {
		return nil
	}

	// A previous removal may have failed. Retry before applying anything, so a
	// stale entry does not silently outlive the attempt to clean it up.
	if t.systemDNSDirty {
		if err := t.revertSystemDNS(); err != nil {
			return xerrors.New("previous system DNS removal still failing").Base(err)
		}
	}

	// The resolver is pointed at the gateway: on FreeBSD the system has no
	// address there, so a query to it is routed into the TUN and answered
	// inside Xray. A query from this host carries the local address.
	address := t.gateway.Addr()
	if err := verifyDNSRouting(ctx, inboundTag, t.local.String(), address.String()); err != nil {
		return xerrors.New("no DNS path at ", address.String(), ":53").Base(err)
	}

	// -x makes this interface's nameserver the only one in use, the
	// equivalent of resolvectl's `domain ~.` plus `default-route true`:
	// without it openresolv keeps the nameservers dhclient supplied listed
	// alongside the gateway, and the system falls back to them.
	if _, err := resolvconfRunner("nameserver "+address.String()+"\n", "-a", t.name, "-x"); err != nil {
		return xerrors.New("resolvconf -a failed").Base(err)
	}
	applied, err := resolvconfApplied(address)
	if err != nil {
		return t.rollbackSystemDNS(xerrors.New("cannot confirm the system DNS").Base(err))
	}
	if !applied {
		return t.rollbackSystemDNS(xerrors.New("resolvconf did not apply ", address.String(), " to any resolver (resolvconf=NO or inclusive_interfaces in resolvconf.conf?)"))
	}

	t.systemDNSSet = true
	xerrors.LogInfo(ctx, "[tun] system DNS set to ", address.String(), " on ", t.name)
	return nil
}

// rollbackSystemDNS undoes a takeover that did not take. A failed removal is
// recorded so the next attempt retries it, and is reported rather than
// swallowed.
func (t *FreeBSDTun) rollbackSystemDNS(cause error) error {
	if _, err := resolvconfRunner("", "-d", t.name); err != nil {
		t.systemDNSDirty = true
		// Combine, because Base overwrites: reporting only the cause would hide
		// the removal failure, and reporting only the removal failure would
		// hide why the removal was attempted.
		return xerrors.New("resolvconf -d failed, the entry may remain").Base(xerrors.Combine(err, cause))
	}
	return cause
}

// revertSystemDNS issues the removal and keeps the dirty flag in step with the
// outcome.
func (t *FreeBSDTun) revertSystemDNS() error {
	_, err := resolvconfRunner("", "-d", t.name)
	t.systemDNSDirty = err != nil
	if err != nil {
		return err
	}
	t.systemDNSSet = false
	return nil
}

// unsetSystemDNS hands DNS back to the OS. Only meaningful when
// ConfigureSystemDNS applied something, or a previous removal failed.
func (t *FreeBSDTun) unsetSystemDNS() {
	if !t.systemDNSSet && !t.systemDNSDirty {
		return
	}
	if err := t.revertSystemDNS(); err != nil {
		xerrors.LogInfoInner(context.Background(), err, "[tun] failed to remove the system DNS entry; run `resolvconf -d ", t.name, "` to clean up")
	}
}

func destroyInterface(name string) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	// struct ifreq: 16-byte name + a 16-byte union (SIOCIFDESTROY's encoded
	// length is 32 bytes on amd64, and the kernel copies in all of it).
	var req struct {
		Name [unix.IFNAMSIZ]byte
		_    [16]byte
	}
	copy(req.Name[:], name)
	_ = ioctlPtr(fd, unix.SIOCIFDESTROY, unsafe.Pointer(&req))
}

func (t *FreeBSDTun) Name() (string, error) {
	return t.device.Name()
}

func (t *FreeBSDTun) Index() (int, error) {
	return t.tunIndex, nil
}

// WritePacket implements GVisorDevice method to write one packet to the tun device
func (t *FreeBSDTun) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.options.MTU) + tunHeaderSize)
	defer b.Release()

	// prepare Unix specific packet header
	_, _ = b.Write([]byte{0x0, 0x0, 0x0, 0x0})
	// copy the bytes of slices that compose the packet into the allocated buffer
	for _, packetElement := range packet.AsSlices() {
		_, _ = b.Write(packetElement)
	}
	// fill Unix specific header from the first raw packet byte, that we can access now
	var family byte
	switch b.Byte(4) >> 4 {
	case 4:
		family = unix.AF_INET
	case 6:
		family = unix.AF_INET6
	default:
		return &tcpip.ErrAborted{}
	}
	b.SetByte(3, family)

	if _, err := t.device.File().Write(b.Bytes()); err != nil {
		if errors.Is(err, unix.EAGAIN) {
			return &tcpip.ErrWouldBlock{}
		}
		return &tcpip.ErrAborted{}
	}
	return nil
}

// ReadPacket implements GVisorDevice method to read one packet from the tun device
// It is expected that the method will not block, rather return ErrQueueEmpty when there is nothing on the line,
// which will make the stack call Wait which should implement desired push-back
func (t *FreeBSDTun) ReadPacket() (byte, *stack.PacketBuffer, error) {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.options.MTU) + tunHeaderSize)

	// read the bytes to the interface file
	n, err := b.ReadFrom(t.device.File())
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}
	if err != nil {
		b.Release()
		return 0, nil, err
	}

	// discard empty or sub-empty packets
	if n <= tunHeaderSize {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}

	// network protocol version from first byte of the raw packet, the one that follows Unix specific header
	version := b.Byte(tunHeaderSize) >> 4
	packetBuffer := buffer.MakeWithData(b.BytesFrom(tunHeaderSize))
	return version, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			b.Release()
		},
	}), nil
}

// Wait some cpu cycles
func (t *FreeBSDTun) Wait() {
	procyield(1)
}

func (t *FreeBSDTun) newEndpoint() (stack.LinkEndpoint, error) {
	return &LinkEndpoint{deviceMTU: t.options.MTU, device: t}, nil
}

const (
	IN6_IFF_NODAD         = 0x0020     // netinet6/in6_var.h
	ND6_INFINITE_LIFETIME = 0xFFFFFFFF // netinet6/nd6.h
)

// ifAliasReq4 is struct in_aliasreq from netinet/in_var.h in the 64-byte
// layout unix.SIOCAIFADDR encodes (name + addr/dstaddr/mask sockaddrs; the
// dstaddr slot is the broadcast address on a broadcast interface).
type ifAliasReq4 struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

// ifAliasReq6 is struct in6_aliasreq from netinet6/in6_var.h. The trailing
// Vhid field matters: unix.SIOCAIFADDR_IN6 is not in x/sys/unix, so
// siocaifaddrIn6 is derived from this struct's size, and the kernel only
// accepts the ioctl whose encoded length matches the real struct.
type ifAliasReq6 struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	Dstaddr    unix.RawSockaddrInet6
	Prefixmask unix.RawSockaddrInet6
	Flags      int32
	Lifetime   addrLifetime6
	Vhid       int32
}

// addrLifetime6 is struct in6_addrlifetime (time_t is int64 on freebsd/amd64).
type addrLifetime6 struct {
	Expire    int64
	Preferred int64
	Vltime    uint32
	Pltime    uint32
}

// SIOCAIFADDR_IN6 = _IOW('i', 27, struct in6_aliasreq); x/sys/unix does not
// carry the netinet6 ioctls, so encode it from the struct size like the
// header macro does.
const siocaifaddrIn6 = 0x80000000 | (uintptr(unsafe.Sizeof(ifAliasReq6{})) << 16) | ('i' << 8) | 27

// setIPAddress assigns the local IPv4 address with the gateway's mask and a
// link-local IPv6 address to the interface, required for the routing to work
// (same scheme as the darwin implementation: local address is the one right
// after the gateway address).
func setIPAddress(name string, gateway netip.Prefix, local netip.Addr, ifIndex int) error {
	socket4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket4)

	local4 := local.As4()

	// The interface runs in broadcast mode (the wireguard tun library puts it
	// there), so the second address slot of the request is the broadcast
	// address, not a point-to-point peer. It stays empty and the kernel
	// derives the broadcast address from the mask; the gateway is then an
	// ordinary on-link address, reachable through the interface route, which
	// is what the system routes and the system DNS takeover need. Filling it
	// with the gateway made the gateway the broadcast address, and a plain
	// socket cannot send to that.
	ifReq4 := ifAliasReq4{
		Addr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   local4,
		},
		Mask: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   prefixMask4(gateway.Bits()),
		},
	}
	copy(ifReq4.Name[:], name)
	if err = ioctlPtr(socket4, unix.SIOCAIFADDR, unsafe.Pointer(&ifReq4)); err != nil {
		return os.NewSyscallError("SIOCAIFADDR", err)
	}

	socket6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket6)

	// link-local ipv6 address with suffix from ipv4, enough for v6 interface
	// routes to be attachable (darwin parity); a link-local address needs its
	// scope, which for FreeBSD ioctls is the interface index
	local6 := netip.AddrFrom16([16]byte{0: 0xfe, 1: 0x80, 12: local4[0], 13: local4[1], 14: local4[2], 15: local4[3]})

	ifReq6 := ifAliasReq6{
		Addr: unix.RawSockaddrInet6{
			Len:      unix.SizeofSockaddrInet6,
			Family:   unix.AF_INET6,
			Addr:     local6.As16(),
			Scope_id: uint32(ifIndex),
		},
		Prefixmask: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   prefixMask6(64),
		},
		Flags: IN6_IFF_NODAD,
		Lifetime: addrLifetime6{
			Vltime: ND6_INFINITE_LIFETIME,
			Pltime: ND6_INFINITE_LIFETIME,
		},
	}
	copy(ifReq6.Name[:], name)
	if err = ioctlPtr(socket6, uint(siocaifaddrIn6), unsafe.Pointer(&ifReq6)); err != nil {
		// non-fatal: FreeBSD auto-configures a link-local address on UP
		// interfaces, which is all the v6 interface routes need
		xerrors.LogInfoInner(context.Background(), os.NewSyscallError("SIOCAIFADDR_IN6", err), "[tun] failed to assign the IPv6 link-local address")
	}

	return nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func prefixMask4(bits int) [4]byte {
	var mask [4]byte
	copy(mask[:], net.CIDRMask(bits, 32))
	return mask
}

func prefixMask6(bits int) [16]byte {
	var mask [16]byte
	copy(mask[:], net.CIDRMask(bits, 128))
	return mask
}

// setinterface is the per-socket half of autoOutboundsInterface. FreeBSD has
// no SO_BINDTODEVICE/IP_BOUND_IF equivalent, so the socket is pointed at the
// escape FIB instead, where Start() mirrors the physical default route; the
// iface argument is resolved by the shared updater but unused here (the escape
// is table-based, not a per-socket interface bind). checkEscapeFib in NewTun
// guarantees the FIB exists before this can run.
func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SETFIB, escapeFib)
}

func (t *FreeBSDTun) setSystemRoutes() error {
	routes, err := buildSystemRoutes(t.options.AutoSystemRoutingTable)
	if err != nil {
		return err
	}
	// Route through the interface, not a gateway: the tun(4) device is a
	// broadcast interface here with no address resolution, so a next hop adds
	// nothing. Interface routes sidestep the gateway entirely (what wg-quick
	// does on FreeBSD).
	for _, destination := range routes {
		if err := execRoute(-1, unix.RTM_ADD, t.tunIndex, destination, netip.Addr{}); err != nil {
			_ = t.unsetSystemRoutes()
			return xerrors.New("failed to add system route ", destination).Base(err)
		}
		t.systemRoutes = append(t.systemRoutes, destination)
	}
	return nil
}

func (t *FreeBSDTun) unsetSystemRoutes() error {
	var errs []error
	for i := len(t.systemRoutes) - 1; i >= 0; i-- {
		destination := t.systemRoutes[i]
		if err := execRoute(-1, unix.RTM_DELETE, t.tunIndex, destination, netip.Addr{}); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, xerrors.New("failed to delete system route ", destination).Base(err))
		}
	}
	t.systemRoutes = nil
	return xerrors.Combine(errs...)
}

func buildSystemRoutes(configured []string) ([]netip.Prefix, error) {
	routes := make([]netip.Prefix, 0, len(configured))
	seen := make(map[netip.Prefix]struct{})

	appendRoute := func(prefix netip.Prefix) {
		prefix = prefix.Masked()
		if _, found := seen[prefix]; found {
			return
		}
		seen[prefix] = struct{}{}
		routes = append(routes, prefix)
	}

	for _, value := range configured {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, xerrors.New("invalid system route ", value).Base(err)
		}
		if prefix.Bits() == 0 {
			for _, protected := range protectedDefaultRoutes(prefix.Addr().Is4()) {
				appendRoute(protected)
			}
			continue
		}
		appendRoute(prefix)
	}

	return routes, nil
}

// protectedDefaultRoutes splits a full default route into eight more-specific
// prefixes covering everything but the zero /8, so the system's real default
// route stays in place for outbound interface discovery (darwin parity).
func protectedDefaultRoutes(ipv4 bool) []netip.Prefix {
	routes := make([]netip.Prefix, 0, 8)
	for i := 0; i < 8; i++ {
		if ipv4 {
			var address [4]byte
			address[0] = 1 << i
			routes = append(routes, netip.PrefixFrom(netip.AddrFrom4(address), 8-i))
		} else {
			var address [16]byte
			address[0] = 1 << i
			routes = append(routes, netip.PrefixFrom(netip.AddrFrom16(address), 8-i))
		}
	}
	return routes
}

// execRoute writes one RTM message to a routing socket. fib >= 0 targets that
// routing table via SO_SETFIB on the routing socket (what route(8) -fib
// does); fib -1 leaves the process default table. An invalid gateway produces
// an interface route pinned to interfaceIndex instead of a gateway route.
func execRoute(fib int, messageType int, interfaceIndex int, destination netip.Prefix, gateway netip.Addr) error {
	message := route.RouteMessage{
		Type:    messageType,
		Version: unix.RTM_VERSION,
		Flags:   unix.RTF_STATIC | unix.RTF_GATEWAY,
		Seq:     1,
	}
	if messageType == unix.RTM_ADD {
		message.Flags |= unix.RTF_UP
	}

	var gatewayAddr route.Addr
	switch {
	case !gateway.IsValid():
		message.Flags &^= unix.RTF_GATEWAY
		message.Index = interfaceIndex
		gatewayAddr = &route.LinkAddr{Index: interfaceIndex}
	case gateway.Is4():
		gatewayAddr = &route.Inet4Addr{IP: gateway.As4()}
	default:
		gatewayAddr = &route.Inet6Addr{IP: gateway.As16()}
	}

	if destination.Addr().Is4() {
		message.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet4Addr{IP: destination.Addr().As4()},
			unix.RTAX_NETMASK: &route.Inet4Addr{IP: prefixMask4(destination.Bits())},
			unix.RTAX_GATEWAY: gatewayAddr,
		}
	} else {
		message.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{IP: destination.Addr().As16()},
			unix.RTAX_NETMASK: &route.Inet6Addr{IP: prefixMask6(destination.Bits())},
			unix.RTAX_GATEWAY: gatewayAddr,
		}
	}

	request, err := message.Marshal()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if fib >= 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SETFIB, fib); err != nil {
			return err
		}
	}
	_, err = unix.Write(fd, request)
	return err
}

func findOutboundInterface(tunIndex int, fixedName string) (*net.Interface, error) {
	if fixedName != "" {
		iface, err := net.InterfaceByName(fixedName)
		if err != nil {
			return nil, err
		}
		if iface.Index == tunIndex {
			return nil, errors.New("outbound interface cannot be the TUN interface")
		}
		return iface, nil
	}

	physical, err := physicalDefaultRoutes(tunIndex, 0)
	if err != nil {
		return nil, err
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, route := range physical {
			if route.family == family {
				return route.iface, nil
			}
		}
	}
	return nil, errors.New("default route not found")
}

// physicalRoute describes one physical default route: the interface it
// leaves through, its gateway, and the connected prefix that makes the
// gateway resolvable.
type physicalRoute struct {
	family    int
	iface     *net.Interface
	gateway   netip.Addr
	connected netip.Prefix
}

// physicalDefaultRoutes scans the default routing table for default routes
// that do not go through the TUN interface, at most one per address family
// (the first usable one wins, matching the darwin implementation's
// preference order). A non-zero onlyIndex restricts the scan to that
// interface, for the fixed-name mode of autoOutboundsInterface.
func physicalDefaultRoutes(tunIndex int, onlyIndex int) ([]physicalRoute, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}

	found := make([]physicalRoute, 0, 2)
	seen := make(map[int]bool)
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok || routeMessage.Index == tunIndex {
			continue
		}
		if onlyIndex != 0 && routeMessage.Index != onlyIndex {
			continue
		}
		if routeMessage.Flags&unix.RTF_UP == 0 || routeMessage.Flags&unix.RTF_GATEWAY == 0 {
			continue
		}

		family, ok := defaultRouteFamily(routeMessage)
		if !ok || seen[family] {
			continue
		}
		iface, err := usableInterface(routeMessage.Index)
		if err != nil {
			continue
		}
		gatewayAddr, ok := routeAddrToNetip(routeMessage.Addrs[unix.RTAX_GATEWAY])
		if !ok {
			continue
		}
		connected, err := connectedPrefix(iface, gatewayAddr)
		if err != nil {
			continue
		}
		seen[family] = true
		found = append(found, physicalRoute{
			family:    family,
			iface:     iface,
			gateway:   gatewayAddr,
			connected: connected,
		})
	}

	if len(found) == 0 {
		return nil, errors.New("default route not found")
	}
	return found, nil
}

// defaultRouteFamily reports the address family of a RIB message that
// represents a true default route (unspecified destination, zero mask).
func defaultRouteFamily(message *route.RouteMessage) (int, bool) {
	if len(message.Addrs) <= unix.RTAX_NETMASK {
		return 0, false
	}

	switch destination := message.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		mask, ok := message.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if !ok || destination.IP != netip.IPv4Unspecified().As4() {
			return 0, false
		}
		ones, bits := net.IPMask(mask.IP[:]).Size()
		return unix.AF_INET, ones == 0 && bits == 32
	case *route.Inet6Addr:
		mask, ok := message.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr)
		if !ok || destination.IP != netip.IPv6Unspecified().As16() {
			return 0, false
		}
		ones, bits := net.IPMask(mask.IP[:]).Size()
		return unix.AF_INET6, ones == 0 && bits == 128
	default:
		return 0, false
	}
}

func usableInterface(index int) (*net.Interface, error) {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, errors.New("default route interface is not usable")
	}
	return iface, nil
}

func routeAddrToNetip(addr route.Addr) (netip.Addr, bool) {
	switch typed := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(typed.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(typed.IP), true
	default:
		return netip.Addr{}, false
	}
}

// checkEscapeFib verifies the system can host the escape routing table at
// all: FIBs are a boot-time resource on FreeBSD.
func checkEscapeFib() error {
	fibs, err := unix.SysctlUint32("net.fibs")
	if err != nil {
		return xerrors.New("failed to read net.fibs").Base(err)
	}
	if fibs < 2 {
		return errors.New("automatic outbound interface on FreeBSD needs a second routing table: add net.fibs=2 to /boot/loader.conf and reboot")
	}
	current, err := unix.SysctlUint32("net.my_fibnum")
	if err != nil {
		return xerrors.New("failed to read net.my_fibnum").Base(err)
	}
	if current == escapeFib {
		return errors.New("xray runs inside routing table 1, which is reserved as the escape table; start it in another FIB")
	}
	return nil
}

// syncEscapeFib mirrors the physical default routes (and the connected
// prefixes their gateways resolve through) into the escape FIB, replacing
// whatever mirror a previous call installed. On discovery failure the old
// mirror is kept, since a stale escape route beats none during a transient
// route flap.
func (t *FreeBSDTun) syncEscapeFib() error {
	var onlyIndex int
	if t.options.AutoOutboundsInterface != "" && updater != nil {
		if iface := updater.Get(); iface != nil {
			onlyIndex = iface.Index
		}
	}
	physical, err := physicalDefaultRoutes(t.tunIndex, onlyIndex)
	if err != nil {
		return err
	}

	desired := make([]escapeRoute, 0, 2*len(physical))
	for _, p := range physical {
		desired = append(desired,
			escapeRoute{prefix: p.connected, ifIndex: p.iface.Index},
			escapeRoute{prefix: defaultPrefix(p.family), ifIndex: p.iface.Index, gateway: p.gateway},
		)
	}

	t.escapeMu.Lock()
	defer t.escapeMu.Unlock()

	// The route monitor hears our own escape FIB writes too; rewriting an
	// unchanged mirror on every wake-up would ping-pong forever.
	if slices.Equal(t.escapeRoutes, desired) {
		return nil
	}

	t.unsetEscapeFibLocked()
	for _, entry := range desired {
		err := execRoute(escapeFib, unix.RTM_ADD, entry.ifIndex, entry.prefix, entry.gateway)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return xerrors.New("failed to add escape route ", entry.prefix).Base(err)
		}
		t.escapeRoutes = append(t.escapeRoutes, entry)
	}
	return nil
}

func (t *FreeBSDTun) unsetEscapeFib() {
	t.escapeMu.Lock()
	defer t.escapeMu.Unlock()
	t.unsetEscapeFibLocked()
}

func (t *FreeBSDTun) unsetEscapeFibLocked() {
	for i := len(t.escapeRoutes) - 1; i >= 0; i-- {
		entry := t.escapeRoutes[i]
		err := execRoute(escapeFib, unix.RTM_DELETE, entry.ifIndex, entry.prefix, entry.gateway)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			xerrors.LogInfoInner(context.Background(), err, "[tun] failed to delete escape route ", entry.prefix)
		}
	}
	t.escapeRoutes = nil
}

func defaultPrefix(family int) netip.Prefix {
	if family == unix.AF_INET {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

// connectedPrefix finds the interface's address prefix containing the
// gateway, which the escape FIB needs as an interface route so the mirrored
// default route's gateway is resolvable there.
func connectedPrefix(iface *net.Interface, gateway netip.Addr) (netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, _ := ipNet.Mask.Size()
		prefix := netip.PrefixFrom(ip, ones).Masked()
		if prefix.Contains(gateway.WithZone("").Unmap()) {
			return prefix, nil
		}
	}
	return netip.Prefix{}, errors.New("no connected prefix contains the gateway")
}
