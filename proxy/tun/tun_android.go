//go:build android

package tun

import (
	"context"
	"net"
	"strconv"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type AndroidTun struct {
	tunFd   int
	options *Config
}

// DefaultTun implements Tun
var _ Tun = (*AndroidTun)(nil)

// AndroidTun implements GVisorDevice, used by the "system" (lite) ip stack
var _ GVisorDevice = (*AndroidTun)(nil)

// fdReadWriter adapts a raw, already non-blocking file descriptor to io.Reader/io.Writer,
// so it can be used with buf.Buffer.ReadFrom, without the ownership/finalizer overhead of
// wrapping it in an *os.File (the fd is owned and closed elsewhere).
type fdReadWriter int

func (f fdReadWriter) Read(p []byte) (int, error) {
	return unix.Read(int(f), p)
}

func (f fdReadWriter) Write(p []byte) (int, error) {
	return unix.Write(int(f), p)
}

// NewTun builds new tun interface handler
func NewTun(options *Config) (Tun, error) {
	fd, err := strconv.Atoi(platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "0" }))
	errors.LogInfo(context.Background(), "read Android Tun Fd ", fd, err)

	err = unix.SetNonblock(fd, true)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return &AndroidTun{
		tunFd:   fd,
		options: options,
	}, nil
}

func (t *AndroidTun) Start() error {
	return nil
}

func (t *AndroidTun) Close() error {
	return nil
}

func (t *AndroidTun) Name() (string, error) {
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return "", err
	}
	if err = unix.IoctlIfreq(t.tunFd, unix.TUNGETIFF, ifr); err != nil {
		return "", err
	}
	return ifr.Name(), nil
}

func (t *AndroidTun) Index() (int, error) {
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

func (t *AndroidTun) newEndpoint() (stack.LinkEndpoint, error) {
	return fdbased.New(&fdbased.Options{
		FDs:               []int{t.tunFd},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
	})
}

// ReadPacket implements GVisorDevice method to read one packet from the tun device, used by
// the "system" (lite) ip stack. The gVisor backed stack instead talks to the fd directly through
// fdbased.New above, for lower overhead batched IO, bypassing GVisorDevice entirely.
// It is expected that the method will not block, rather return ErrQueueEmpty when there is nothing on the line,
// which will make the stack call Wait which should implement desired push-back
func (t *AndroidTun) ReadPacket() (byte, *stack.PacketBuffer, error) {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.options.MTU))

	// read the bytes from the interface file descriptor, which is already non-blocking
	n, err := b.ReadFrom(fdReadWriter(t.tunFd))
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}
	if err != nil {
		b.Release()
		return 0, nil, err
	}

	// discard empty packets
	if n == 0 {
		b.Release()
		return 0, nil, ErrQueueEmpty
	}

	// network protocol version from the first nibble of the raw packet
	version := b.Byte(0) >> 4
	packetBuffer := buffer.MakeWithData(b.Bytes())
	return version, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			b.Release()
		},
	}), nil
}

// WritePacket implements GVisorDevice method to write one packet to the tun device
func (t *AndroidTun) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.options.MTU))
	defer b.Release()

	// copy the bytes of slices that compose the packet into the allocated buffer, no
	// extra header is needed here, unlike Darwin/FreeBSD's utun devices
	for _, packetElement := range packet.AsSlices() {
		_, _ = b.Write(packetElement)
	}

	if _, err := fdReadWriter(t.tunFd).Write(b.Bytes()); err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return &tcpip.ErrWouldBlock{}
		}
		return &tcpip.ErrAborted{}
	}
	return nil
}

// Wait blocks until the tun fd is likely readable again, rather than spinning the CPU.
// A bounded timeout keeps this responsive to a Close() racing a call already parked here.
func (t *AndroidTun) Wait() {
	fds := []unix.PollFd{{Fd: int32(t.tunFd), Events: unix.POLLIN}}
	_, _ = unix.Poll(fds, 1000)
}

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	return unix.BindToDevice(int(fd), iface.Name)
}

func findOutboundInterface(tunIndex int, fixedName string) (*net.Interface, error) {
	if fixedName == "" {
		return nil, errors.New("automatic outbound interface selection is not supported on this platform")
	}
	iface, err := net.InterfaceByName(fixedName)
	if err != nil {
		return nil, err
	}
	if iface.Index == tunIndex {
		return nil, errors.New("outbound interface cannot be the TUN interface")
	}
	return iface, nil
}
