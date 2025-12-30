//go:build windows

package tun

import (
	"context"
	"errors"
	_ "unsafe"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// WintunEndpoint implements GVisor stack.LinkEndpoint
var _ stack.LinkEndpoint = (*WintunEndpoint)(nil)

type WintunEndpoint struct {
	tun              *WindowsTun
	dispatcherCancel context.CancelFunc
}

var ErrUnsupportedNetworkProtocol = errors.New("unsupported ip version")

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

func (e *WintunEndpoint) MTU() uint32 {
	return e.tun.MTU
}

func (e *WintunEndpoint) SetMTU(mtu uint32) {
	// not Implemented, as it is not expected GVisor will be asking tun device to be modified
}

func (e *WintunEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *WintunEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *WintunEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	// not Implemented, as it is not expected GVisor will be asking tun device to be modified
}

func (e *WintunEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *WintunEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
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

func (e *WintunEndpoint) IsAttached() bool {
	return e.dispatcherCancel != nil
}

func (e *WintunEndpoint) Wait() {

}

func (e *WintunEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *WintunEndpoint) AddHeader(buffer *stack.PacketBuffer) {
	// tun interface doesn't have link layer header, it will be added by the OS
}

func (e *WintunEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (e *WintunEndpoint) Close() {
	if e.dispatcherCancel != nil {
		e.dispatcherCancel()
		e.dispatcherCancel = nil
	}
}

func (e *WintunEndpoint) SetOnCloseAction(f func()) {

}

func (e *WintunEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	// for all packets in the list to send
	for _, packetBuffer := range packetBufferList.AsSlice() {
		// request buffer from Wintun
		packet, err := e.tun.session.AllocateSendPacket(packetBuffer.Size())
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}

		// copy the bytes of slices that compose the packet into the allocated buffer
		var index int
		for _, packetElement := range packetBuffer.AsSlices() {
			index += copy(packet[index:], packetElement)
		}

		// signal Wintun to send that buffer as the packet
		e.tun.session.SendPacket(packet)
		n++
	}
	return n, nil
}

func (e *WintunEndpoint) readPacket() (tcpip.NetworkProtocolNumber, *stack.PacketBuffer, error) {
	packet, err := e.tun.session.ReceivePacket()
	if err != nil {
		return 0, nil, err
	}

	var networkProtocol tcpip.NetworkProtocolNumber
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		networkProtocol = header.IPv4ProtocolNumber
	case header.IPv6Version:
		networkProtocol = header.IPv6ProtocolNumber
	default:
		e.tun.session.ReleaseReceivePacket(packet)
		return 0, nil, ErrUnsupportedNetworkProtocol
	}

	packetBuffer := buffer.MakeWithView(buffer.NewViewWithData(packet))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           packetBuffer,
		IsForwardedPacket: true,
		OnRelease: func() {
			e.tun.session.ReleaseReceivePacket(packet)
		},
	})
	return networkProtocol, pkt, nil
}

func (e *WintunEndpoint) dispatchLoop(ctx context.Context, dispatcher stack.NetworkDispatcher) {
	readWait := e.tun.session.ReadWaitEvent()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			networkProtocolNumber, packet, err := e.readPacket()
			// read queue empty, yield slightly, wait for the spinlock, retry
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				procyield(1)
				_, _ = windows.WaitForSingleObject(readWait, windows.INFINITE)
				continue
			}
			// discard unknown network protocol packet
			if errors.Is(err, ErrUnsupportedNetworkProtocol) {
				continue
			}
			// stop dispatcher loop on any other interface failure
			if err != nil {
				e.Attach(nil)
				continue
			}

			// dispatch the buffer to the stack
			dispatcher.DeliverNetworkPacket(networkProtocolNumber, packet)
			// signal the buffer that it can be released
			packet.DecRef()
		}
	}
}
