//go:build darwin

package tun

import (
	"context"
	"errors"
	_ "unsafe"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const utunHeaderSize = 4

var ErrUnsupportedNetworkProtocol = errors.New("unsupported ip version")

var ErrQueueEmpty = errors.New("queue is empty")

// DarwinEndpoint implements GVisor stack.LinkEndpoint
var _ stack.LinkEndpoint = (*DarwinEndpoint)(nil)

type DarwinEndpoint struct {
	tun              *DarwinTun
	dispatcherCancel context.CancelFunc
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

func (e *DarwinEndpoint) MTU() uint32 {
	return e.tun.options.MTU
}

func (e *DarwinEndpoint) SetMTU(_ uint32) {
	// not Implemented, as it is not expected GVisor will be asking tun device to be modified
}

func (e *DarwinEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *DarwinEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *DarwinEndpoint) SetLinkAddress(_ tcpip.LinkAddress) {
	// not Implemented, as it is not expected GVisor will be asking tun device to be modified
}

func (e *DarwinEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *DarwinEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}

	if dispatcher != nil {
		ctx, cancel := context.WithCancel(context.Background())
		go e.dispatchLoop(ctx, dispatcher)
		e.dispatcherCancel = cancel
	}
}

func (e *DarwinEndpoint) IsAttached() bool {
	return e.dispatcherCancel != nil
}

func (e *DarwinEndpoint) Wait() {

}

func (e *DarwinEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *DarwinEndpoint) AddHeader(buffer *stack.PacketBuffer) {
	// tun interface doesn't have link layer header, it will be added by the OS
}

func (e *DarwinEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (e *DarwinEndpoint) Close() {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}
}

func (e *DarwinEndpoint) SetOnCloseAction(_ func()) {

}

func (e *DarwinEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, packetBuffer := range packetBufferList.AsSlice() {
		family, err := ipFamilyFromPacket(packetBuffer)
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}

		// request memory to write from reusable buffer pool
		b := buf.NewWithSize(int32(e.tun.options.MTU) + utunHeaderSize)

		// build Darwin specific packet header
		_, _ = b.Write([]byte{0x0, 0x0, 0x0, byte(family)})
		// copy the bytes of slices that compose the packet into the allocated buffer
		for _, packetElement := range packetBuffer.AsSlices() {
			_, _ = b.Write(packetElement)
		}

		if _, err := e.tun.tunFile.Write(b.Bytes()); err != nil {
			if errors.Is(err, unix.EAGAIN) {
				return n, &tcpip.ErrWouldBlock{}
			}
			return n, &tcpip.ErrAborted{}
		}
		b.Release()
		n++
	}
	return n, nil
}

func (e *DarwinEndpoint) readPacket() (tcpip.NetworkProtocolNumber, *stack.PacketBuffer, error) {
	// request memory to write from reusable buffer pool
	b := buf.NewWithSize(int32(e.tun.options.MTU) + utunHeaderSize)

	// read the bytes to the buffer
	n, err := b.ReadFrom(e.tun.tunFile)
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

	var networkProtocol tcpip.NetworkProtocolNumber
	switch b.Byte(3) {
	case unix.AF_INET:
		networkProtocol = header.IPv4ProtocolNumber
	case unix.AF_INET6:
		networkProtocol = header.IPv6ProtocolNumber
	default:
		b.Release()
		return 0, nil, ErrUnsupportedNetworkProtocol
	}

	packetBuffer := buffer.MakeWithData(b.BytesFrom(utunHeaderSize))
	return networkProtocol, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			b.Release()
		},
	}), nil
}

func (e *DarwinEndpoint) dispatchLoop(ctx context.Context, dispatcher stack.NetworkDispatcher) {

	for {
		select {
		case <-ctx.Done():
			return
		default:
			networkProtocolNumber, packet, err := e.readPacket()
			// read queue empty, yield slightly, wait for the spinlock, retry
			if errors.Is(err, ErrQueueEmpty) {
				procyield(1)
				continue
			}
			// discard unknown network protocol packet
			if errors.Is(err, ErrUnsupportedNetworkProtocol) {
				continue
			}
			// stop dispatcher loop on any other interface failure
			if err != nil {
				e.Attach(nil)
				return
			}

			// dispatch the buffer to the stack
			dispatcher.DeliverNetworkPacket(networkProtocolNumber, packet)
			// signal the buffer that it can be released
			packet.DecRef()
		}
	}
}

func ipFamilyFromPacket(packetBuffer *stack.PacketBuffer) (int, error) {
	for _, slice := range packetBuffer.AsSlices() {
		if len(slice) == 0 {
			continue
		}
		switch header.IPVersion(slice) {
		case header.IPv4Version:
			return unix.AF_INET, nil
		case header.IPv6Version:
			return unix.AF_INET6, nil
		default:
			return 0, ErrUnsupportedNetworkProtocol
		}
	}
	return 0, errors.New("empty packet")
}
