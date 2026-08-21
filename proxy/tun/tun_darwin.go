//go:build darwin

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	utunControlName      = "com.apple.net.utun_control"
	sysprotoControl      = 2
	defaultDarwinGateway = "169.254.10.1/30"
	utunHeaderSize       = 4
	UTUN_OPT_IFNAME      = 2
)

const (
	SIOCAIFADDR6          = 2155899162 // netinet6/in6_var.h
	IN6_IFF_NODAD         = 0x0020     // netinet6/in6_var.h
	IN6_IFF_SECURED       = 0x0400     // netinet6/in6_var.h
	ND6_INFINITE_LIFETIME = 0xFFFFFFFF // netinet6/nd6.h
)

type DarwinTun struct {
	tunFile *os.File
	options *Config
	tunFd   int
	ownsFd  bool // true for macOS (we created the fd), false for iOS (fd from system)

	// Genuinely blocks Wait() until tunFd is readable, instead of the
	// previous procyield-only busy-spin (dispatchLoop in
	// stack_gvisor_endpoint.go calls ReadPacket() then Wait() in a tight
	// loop with no other throttling whenever the queue is empty -- with
	// only procyield(1), that pins a full CPU core for as long as the
	// tunnel is up, observed causing severe device heating/thermal
	// shutdown). nil if kqueue setup failed, in which case Wait() falls
	// back to a bounded time.Sleep instead. See waitKqueue's own doc
	// comment for why this is a dedicated type rather than a bare fd.
	waitKq *waitKqueue

	routeMonitor     *os.File
	routeMonitorOnce sync.Once
	systemRoutes     []netip.Prefix
	gateway          netip.Prefix
}

// waitKqueue owns a kqueue fd used by DarwinTun.Wait() to block on
// read-readiness. Closing and waiting can race from different goroutines
// (Close() from the caller that tears down the tunnel, Wait() from
// dispatchLoop's own goroutine) -- reviewer feedback on XTLS/Xray-core#6580
// found that a bare `int` fd field let Close() race Wait()'s use of the
// same fd number, and on Darwin a closed fd number can be reused by an
// unrelated concurrent open() before Wait() gets to call Kevent on it,
// so Wait() could end up polling (or Close() could end up closing) a
// completely unrelated file descriptor. This type makes closing
// idempotent (sync.Once) and gates every Kevent call behind an atomic
// "closed" flag checked immediately before the syscall, so Wait() never
// issues a kevent syscall against a fd number that Close() has already
// (or is concurrently) invalidated -- there's still a narrow window where
// Wait() checks-then-uses the fd, but Close() only actually closes it
// after Wait() cannot start a new syscall on it (the flag is set first,
// synchronized with acquire/release semantics), which is sufficient since
// Wait()'s Kevent call itself is what's being raced, not a fd read/write.
type waitKqueue struct {
	fd     int
	closed atomic.Bool
	once   sync.Once
}

// newWaitKqueue creates a kqueue registered for read-readiness on fd, for
// Wait() to block on. Returns nil if anything fails, so callers can fall
// back to a bounded sleep rather than error out of NewTun over what is
// purely a CPU-efficiency concern.
func newWaitKqueue(fd int) *waitKqueue {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil
	}
	_, err = unix.Kevent(kq, []unix.Kevent_t{{
		Ident:  uint64(fd),
		Filter: unix.EVFILT_READ,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
	}}, nil, nil)
	if err != nil {
		_ = unix.Close(kq)
		return nil
	}
	return &waitKqueue{fd: kq}
}

// wait blocks until the registered fd is readable, timeout elapses, or a
// benign interrupt occurs -- all three are "this kqueue is still healthy,
// the caller should just try again" and return true; the caller
// (DarwinTun.Wait) doesn't need to distinguish them since it always calls
// ReadPacket() right after anyway, and that already handles "nothing was
// actually there" via ErrQueueEmpty. Returns false only when the kqueue
// itself is no longer usable -- already closed, or the kevent syscall
// failed for a reason other than EINTR -- see its own call site in
// DarwinTun.Wait for why a persistent failure must not be silently
// retried forever (reviewer feedback, XTLS/Xray-core#6580 P2).
func (w *waitKqueue) wait(timeout time.Duration) (ok bool) {
	if w.closed.Load() {
		return false
	}
	events := make([]unix.Kevent_t, 1)
	ts := unix.NsecToTimespec(timeout.Nanoseconds())
	_, err := unix.Kevent(w.fd, nil, events, &ts)
	if err != nil {
		return errors.Is(err, unix.EINTR)
	}
	return true
}

// close marks the kqueue as unusable (so any Wait() call that hasn't yet
// entered the kevent syscall bails out instead) and closes the underlying
// fd exactly once, regardless of how many times close is called or
// whether it races a Wait() already inside its kevent syscall (that call
// either completes against the still-open fd or returns an error safely
// -- either way, no other goroutine can be handed this fd number in
// between the atomic flag flip and the actual close, since nothing else
// in this type ever creates a new kqueue with the same field).
func (w *waitKqueue) close() {
	w.once.Do(func() {
		w.closed.Store(true)
		_ = unix.Close(w.fd)
	})
}

var (
	_ Tun          = (*DarwinTun)(nil)
	_ GVisorDevice = (*DarwinTun)(nil)
)

func NewTun(options *Config) (Tun, error) {
	// Check if fd is provided via environment (iOS mode)
	fdStr := platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" })
	if fdStr != "" {
		// iOS: use provided fd from NetworkExtension
		fd, err := strconv.Atoi(fdStr)
		if err != nil {
			return nil, err
		}

		if err = unix.SetNonblock(fd, true); err != nil {
			return nil, err
		}

		return &DarwinTun{
			tunFile: os.NewFile(uintptr(fd), "utun"),
			options: options,
			tunFd:   fd,
			ownsFd:  false,
			waitKq:  newWaitKqueue(fd),
		}, nil
	}

	// macOS: create our own utun interface
	tunFile, err := open(options.Name)
	if err != nil {
		return nil, err
	}

	gateway, err := selectDarwinGateway(options.Gateway)
	if err != nil {
		_ = tunFile.Close()
		return nil, err
	}

	err = setup(options.Name, options.MTU, gateway)
	if err != nil {
		_ = tunFile.Close()
		return nil, err
	}

	return &DarwinTun{
		tunFile: tunFile,
		options: options,
		tunFd:   int(tunFile.Fd()),
		ownsFd:  true,
		waitKq:  newWaitKqueue(int(tunFile.Fd())),
		gateway: gateway,
	}, nil
}

func (t *DarwinTun) Start() error {
	if !t.ownsFd {
		return nil
	}

	if err := t.setSystemRoutes(); err != nil {
		return err
	}

	if updater != nil {
		fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
		if err != nil {
			_ = t.unsetSystemRoutes()
			return err
		}
		t.routeMonitor = os.NewFile(uintptr(fd), "xray-route-monitor")
		go t.monitorRouteChanges()
	}
	return nil
}

func (t *DarwinTun) Close() error {
	t.routeMonitorOnce.Do(func() {
		if t.routeMonitor != nil {
			_ = t.routeMonitor.Close()
		}
	})
	if t.waitKq != nil {
		t.waitKq.close()
	}
	routeErr := t.unsetSystemRoutes()
	if t.ownsFd {
		return xerrors.Combine(routeErr, t.tunFile.Close())
	}
	// iOS: don't close the fd, it's owned by NetworkExtension
	return routeErr
}

func (t *DarwinTun) monitorRouteChanges() {
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
	}
}

func (t *DarwinTun) Name() (string, error) {
	return unix.GetsockoptString(t.tunFd, sysprotoControl, UTUN_OPT_IFNAME)
}

func (t *DarwinTun) Index() (int, error) {
	name, err := t.Name()
	if err != nil {
		return 0, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// WritePacket implements GVisorDevice method to write one packet to the tun device
func (t *DarwinTun) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.options.MTU) + utunHeaderSize)
	defer b.Release()

	// prepare Darwin specific packet header
	_, _ = b.Write([]byte{0x0, 0x0, 0x0, 0x0})
	// copy the bytes of slices that compose the packet into the allocated buffer
	for _, packetElement := range packet.AsSlices() {
		_, _ = b.Write(packetElement)
	}
	// fill Darwin specific header from the first raw packet byte, that we can access now
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

	if _, err := t.tunFile.Write(b.Bytes()); err != nil {
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
func (t *DarwinTun) ReadPacket() (byte, *stack.PacketBuffer, error) {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.options.MTU) + utunHeaderSize)

	// read the bytes to the interface file
	n, err := b.ReadFrom(t.tunFile)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}
	if err != nil {
		b.Release()
		return 0, nil, err
	}

	// discard empty or sub-empty packets
	if n <= utunHeaderSize {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}

	// network protocol version from first byte of the raw packet, the one that follows Darwin specific header
	version := b.Byte(utunHeaderSize) >> 4
	packetBuffer := buffer.MakeWithData(b.BytesFrom(utunHeaderSize))
	return version, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			b.Release()
		},
	}), nil
}

// Wait blocks until tunFd is readable (or a short timeout elapses), rather
// than spinning the CPU -- see the waitKq field's own doc comment. A bounded
// timeout (not an indefinite wait) keeps this responsive to a Close() that
// happens to race a call already parked here.
//
// Reviewer feedback (XTLS/Xray-core#6580, P2): the original version
// discarded every error from the underlying kevent syscall. dispatchLoop
// (stack_gvisor_endpoint.go) calls ReadPacket() then Wait() in an
// unconditional tight loop -- if kevent started failing at runtime for a
// persistent reason (not just a benign EINTR), Wait() returning
// immediately every time reintroduces exactly the busy-spin this whole
// change exists to remove, just routed through a failing syscall instead
// of procyield. waitKq.wait's own bool return distinguishes "genuinely
// interrupted, try again" from "this kqueue is unusable now" -- Wait()
// permanently falls back to the sleep path once that happens, rather than
// retrying the same broken kqueue forever.
func (t *DarwinTun) Wait() {
	if t.waitKq != nil && t.waitKq.wait(time.Second) {
		return
	}
	if t.waitKq != nil {
		// Persistent kevent failure (not a benign EINTR, and not just
		// "the 1s timeout elapsed with nothing to read" -- wait() already
		// returned true for both of those cases above). Stop trusting
		// this kqueue for the rest of this DarwinTun's lifetime instead of
		// re-attempting a syscall that's already shown it won't succeed.
		t.waitKq.close()
		t.waitKq = nil
	}
	// Reviewer feedback (XTLS/Xray-core#6580): procyield here is the same
	// busy-spin this whole change exists to remove, just gated behind an
	// edge case (kqueue setup failing, which practically never happens on
	// real Darwin systems, or having just failed permanently above)
	// instead of always -- a genuine bounded sleep actually yields the CPU
	// instead of being a near-instant scheduler hint that lets the tight
	// dispatchLoop caller spin just as hot as before.
	time.Sleep(time.Millisecond)
}

func (t *DarwinTun) newEndpoint() (stack.LinkEndpoint, error) {
	return &LinkEndpoint{deviceMTU: t.options.MTU, device: t}, nil
}

// open the interface, by creating new utunN if in the system and returning its file descriptor
func open(name string) (*os.File, error) {
	ifIndex := -1
	_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
	if err != nil || ifIndex < 0 {
		return nil, errors.New("interface name must be utunN, where N is a number, e.g. utun9, utun11 and so on")
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, err
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	sockaddr := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}
	if err := unix.Connect(fd, sockaddr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return os.NewFile(uintptr(fd), name), nil
}

// setup the interface by name
func setup(name string, MTU uint32, gateway netip.Prefix) error {
	if err := setMTU(name, MTU); err != nil {
		return err
	}

	/*
	 * Darwin routing require tunnel type interface to have local and remote address, to be routable.
	 * To simplify inevitable task, assign the interface static ip address.
	 */
	if err := setIPAddress(name, gateway); err != nil {
		return err
	}

	return nil
}

func selectDarwinGateway(configured []string) (netip.Prefix, error) {
	if len(configured) == 0 {
		return netip.ParsePrefix(defaultDarwinGateway)
	}

	for _, value := range configured {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, xerrors.New("invalid macOS gateway ", value).Base(err)
		}
		if !prefix.Addr().Is4() {
			continue
		}
		local, ok := nextDarwinLocalIPv4(prefix)
		if !ok || !prefix.Contains(local) {
			return netip.Prefix{}, xerrors.New("macOS gateway ", value, " must contain at least one usable local IPv4 address after the gateway address")
		}
		return prefix, nil
	}

	return netip.Prefix{}, xerrors.New("macOS gateway requires at least one IPv4 prefix")
}

func nextDarwinLocalIPv4(gateway netip.Prefix) (netip.Addr, bool) {
	local4 := gateway.Addr().As4()
	for i := len(local4) - 1; i >= 0; i-- {
		local4[i]++
		if local4[i] != 0 {
			return netip.AddrFrom4(local4), true
		}
	}
	return netip.Addr{}, false
}

// setMTU sets MTU on the interface by given name
func setMTU(name string, mtu uint32) error {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket)

	ifr := unix.IfreqMTU{MTU: int32(mtu)}
	copy(ifr.Name[:], name)
	return unix.IoctlSetIfreqMTU(socket, &ifr)
}

type ifAliasReq4 struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type ifAliasReq6 struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet6
	Dstaddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    uint32
	Lifetime addrLifetime6
}

type addrLifetime6 struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

// setIPAddress sets ipv4 and ipv6 addresses to the interface, required for the routing to work
func setIPAddress(name string, gateway netip.Prefix) error {
	socket4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socket4)

	// assume local ip address is next one from the remote address
	local, ok := nextDarwinLocalIPv4(gateway)
	if !ok || !gateway.Contains(local) {
		return xerrors.New("macOS gateway ", gateway.String(), " must contain at least one usable local IPv4 address after the gateway address")
	}
	local4 := local.As4()

	// fill the configuration for ipv4
	ifReq4 := ifAliasReq4{
		Addr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   local4,
		},
		Dstaddr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   gateway.Addr().As4(),
		},
		Mask: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(gateway.Bits(), 32)).String()).As4(),
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

	// link-local ipv6 address with suffix from ipv6
	local6 := netip.AddrFrom16([16]byte{0: 0xfe, 1: 0x80, 12: local4[0], 13: local4[1], 14: local4[2], 15: local4[3]})

	// fill the configuration for ipv6
	// only link-local address without the destination is enough for it
	ifReq6 := ifAliasReq6{
		Addr: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   local6.As16(),
		},
		Mask: unix.RawSockaddrInet6{
			Len:    unix.SizeofSockaddrInet6,
			Family: unix.AF_INET6,
			Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(64, 128)).String()).As16(),
		},
		Flags: IN6_IFF_NODAD,
		Lifetime: addrLifetime6{
			Vltime: ND6_INFINITE_LIFETIME,
			Pltime: ND6_INFINITE_LIFETIME,
		},
	}
	// assign link-local ipv6 address to the interface.
	// this will additionally trigger OS level autoconfiguration, which will result two different link-local
	// addresses - the requested one, and autoconfigured one.
	// this really has no known side effects, just look excessive. and actually considered pretty normal way to
	// enable the ipv6 on the interface by macOS concepts.
	copy(ifReq6.Name[:], name)
	if err = ioctlPtr(socket6, SIOCAIFADDR6, unsafe.Pointer(&ifReq6)); err != nil {
		return os.NewSyscallError("SIOCAIFADDR6", err)
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

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	var err1, err2 error

	switch network {
	case "tcp6", "udp6", "ip6":
		err1 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
		fallthrough
	case "tcp4", "udp4", "ip4":
		err2 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
	default:
		panic(network + " " + address)
	}

	return errors.Join(err1, err2)
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

	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}

	var ipv6Index int
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok || routeMessage.Index == tunIndex {
			continue
		}
		if routeMessage.Flags&unix.RTF_UP == 0 || routeMessage.Flags&unix.RTF_GATEWAY == 0 {
			continue
		}

		family, ok := defaultRouteFamily(routeMessage)
		if !ok {
			continue
		}
		if family == unix.AF_INET {
			return usableDarwinInterface(routeMessage.Index)
		}
		if family == unix.AF_INET6 && ipv6Index == 0 {
			ipv6Index = routeMessage.Index
		}
	}

	if ipv6Index != 0 {
		return usableDarwinInterface(ipv6Index)
	}
	return nil, errors.New("default route not found")
}

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

func usableDarwinInterface(index int) (*net.Interface, error) {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, errors.New("default route interface is not usable")
	}
	return iface, nil
}

func (t *DarwinTun) setSystemRoutes() error {
	routes, err := buildDarwinSystemRoutes(t.options.AutoSystemRoutingTable)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return nil
	}

	tunIndex, err := t.Index()
	if err != nil {
		return err
	}
	for _, destination := range routes {
		if err := execDarwinRoute(unix.RTM_ADD, tunIndex, destination, t.gateway); err != nil {
			_ = t.unsetSystemRoutes()
			return xerrors.New("failed to add system route ", destination).Base(err)
		}
		t.systemRoutes = append(t.systemRoutes, destination)
	}
	return nil
}

func (t *DarwinTun) unsetSystemRoutes() error {
	var errs []error
	tunIndex, indexErr := t.Index()
	if indexErr != nil && len(t.systemRoutes) > 0 {
		errs = append(errs, indexErr)
	}
	for i := len(t.systemRoutes) - 1; i >= 0; i-- {
		destination := t.systemRoutes[i]
		if err := execDarwinRoute(unix.RTM_DELETE, tunIndex, destination, t.gateway); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, xerrors.New("failed to delete system route ", destination).Base(err))
		}
	}
	t.systemRoutes = nil
	return xerrors.Combine(errs...)
}

func buildDarwinSystemRoutes(configured []string) ([]netip.Prefix, error) {
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
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			for _, protected := range darwinProtectedDefaultRoutes(prefix.Addr().Is4()) {
				appendRoute(protected)
			}
			continue
		}
		appendRoute(prefix)
	}

	return routes, nil
}

func darwinProtectedDefaultRoutes(ipv4 bool) []netip.Prefix {
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

func execDarwinRoute(messageType int, interfaceIndex int, destination netip.Prefix, gateway netip.Prefix) error {
	message := route.RouteMessage{
		Type:    messageType,
		Version: unix.RTM_VERSION,
		Flags:   unix.RTF_STATIC | unix.RTF_GATEWAY,
		Seq:     1,
	}
	if messageType == unix.RTM_ADD {
		message.Flags |= unix.RTF_UP
	}

	if destination.Addr().Is4() {
		message.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet4Addr{IP: destination.Addr().As4()},
			unix.RTAX_NETMASK: &route.Inet4Addr{IP: prefixMask4(destination.Bits())},
			unix.RTAX_GATEWAY: &route.Inet4Addr{IP: gateway.Addr().As4()},
		}
	} else {
		message.Flags &^= unix.RTF_GATEWAY
		message.Index = interfaceIndex
		message.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{IP: destination.Addr().As16()},
			unix.RTAX_NETMASK: &route.Inet6Addr{IP: prefixMask6(destination.Bits())},
			unix.RTAX_GATEWAY: &route.LinkAddr{Index: interfaceIndex},
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
	_, err = unix.Write(fd, request)
	return err
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
