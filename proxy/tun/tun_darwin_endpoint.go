//go:build darwin

package tun

import (
	"context"
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const utunHeaderSize = 4

var ErrUnsupportedNetworkProtocol = errors.New("unsupported ip version")

// DarwinEndpoint implements GVisor stack.LinkEndpoint
var _ stack.LinkEndpoint = (*DarwinEndpoint)(nil)

type DarwinEndpoint struct {
	tunFd            int
	mtu              uint32
	dispatcherCancel context.CancelFunc
}

func newDarwinEndpoint(tunFd int, mtu uint32) *DarwinEndpoint {
	return &DarwinEndpoint{
		tunFd: tunFd,
		mtu:   mtu,
	}
}

func (e *DarwinEndpoint) MTU() uint32 {
	return e.mtu
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

		var headerBytes [utunHeaderSize]byte
		binary.BigEndian.PutUint32(headerBytes[:], family)

		writeSlices := append([][]byte{headerBytes[:]}, packetBuffer.AsSlices()...)
		if _, err := unix.Writev(e.tunFd, writeSlices); err != nil {
			if errors.Is(err, unix.EAGAIN) {
				return n, &tcpip.ErrWouldBlock{}
			}
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

func (e *DarwinEndpoint) dispatchLoop(ctx context.Context, dispatcher stack.NetworkDispatcher) {
	readSize := int(e.mtu)
	if readSize <= 0 {
		readSize = 65535
	}
	readSize += utunHeaderSize

	buf := make([]byte, readSize)
	for ctx.Err() == nil {

		n, err := unix.Read(e.tunFd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			e.Attach(nil)
			return
		}
		if n <= utunHeaderSize {
			continue
		}

		networkProtocol, packet, err := parseUTunPacket(buf[:n])
		if errors.Is(err, ErrUnsupportedNetworkProtocol) {
			continue
		}
		if err != nil {
			e.Attach(nil)
			return
		}

		dispatcher.DeliverNetworkPacket(networkProtocol, packet)
		packet.DecRef()
	}
}

func parseUTunPacket(packet []byte) (tcpip.NetworkProtocolNumber, *stack.PacketBuffer, error) {
	if len(packet) <= utunHeaderSize {
		return 0, nil, errors.New("packet too short")
	}

	family := binary.BigEndian.Uint32(packet[:utunHeaderSize])
	var networkProtocol tcpip.NetworkProtocolNumber
	switch family {
	case uint32(unix.AF_INET):
		networkProtocol = header.IPv4ProtocolNumber
	case uint32(unix.AF_INET6):
		networkProtocol = header.IPv6ProtocolNumber
	default:
		return 0, nil, ErrUnsupportedNetworkProtocol
	}

	payload := packet[utunHeaderSize:]
	packetBuffer := buffer.MakeWithData(payload)
	return networkProtocol, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
	}), nil
}

func ipFamilyFromPacket(packetBuffer *stack.PacketBuffer) (uint32, error) {
	for _, slice := range packetBuffer.AsSlices() {
		if len(slice) == 0 {
			continue
		}
		switch header.IPVersion(slice) {
		case header.IPv4Version:
			return uint32(unix.AF_INET), nil
		case header.IPv6Version:
			return uint32(unix.AF_INET6), nil
		default:
			return 0, ErrUnsupportedNetworkProtocol
		}
	}
	return 0, errors.New("empty packet")
}
