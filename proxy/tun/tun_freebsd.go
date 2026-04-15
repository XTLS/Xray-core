//go:build freebsd

package tun

import (
	"errors"
	"net"
	_ "unsafe"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/buf"
)

const tunHeaderSize = 4

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

type FreeBSDTun struct {
	device tun.Device
	mtu    uint32
}

var _ Tun = (*FreeBSDTun)(nil)
var _ GVisorDevice = (*FreeBSDTun)(nil)

// NewTun builds new tun interface handler
func NewTun(options *Config) (Tun, error) {
	tunDev, err := tun.CreateTUN(options.Name, int(options.MTU))
	if err != nil {
		return nil, err
	}

	return &FreeBSDTun{device: tunDev, mtu: options.MTU}, nil
}

func (t *FreeBSDTun) Start() error {
	return nil
}

func (t *FreeBSDTun) Close() error {
	return t.device.Close()
}

func (t *FreeBSDTun) Name() (string, error) {
	return t.device.Name()
}

func (t *FreeBSDTun) Index() (int, error) {
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
func (t *FreeBSDTun) WritePacket(packet *stack.PacketBuffer) tcpip.Error {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(t.mtu) + tunHeaderSize)
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
	b := buf.NewWithSize(int32(t.mtu) + tunHeaderSize)

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
	return &LinkEndpoint{deviceMTU: t.mtu, device: t}, nil
}

func setinterface(network, address string, fd uintptr, iface *net.Interface) error {
	return nil
}
