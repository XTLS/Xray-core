/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/sagernet/wireguard-go/tun"
	xnet "github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	hasV4, hasV6   bool
}

type Net netTun

func CreateNetTUN(localAddresses []netip.Addr, mtu int, handleLocal bool) (tun.Device, *Net, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        handleLocal,
	}
	dev := &netTun{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 1),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}
	dev.ep.AddNotify(dev)
	tcpipErr := dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	if !handleLocal {
		// enable promiscuous mode to handle all packets processed by netstack
		dev.stack.SetPromiscuousMode(1, true)
		dev.stack.SetSpoofing(1, true)
	}

	opt := tcpip.CongestionControlOption("cubic")
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		return nil, nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%s)): %s", tcp.ProtocolNumber, opt, opt, err)
	}

	dev.events <- tun.EventUp
	return dev, (*Net)(dev), nil
}

// Name implements tun.Device
func (tun *netTun) Name() (string, error) {
	return "go", nil
}

// File implements tun.Device
func (tun *netTun) File() *os.File {
	return nil
}

// Events implements tun.Device
func (tun *netTun) Events() chan tun.Event {
	return tun.events
}

// Read implements tun.Device
func (tun *netTun) Read(buf []byte, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	return view.Read(buf[offset:])
}

// Write implements tun.Device
func (tun *netTun) Write(buf []byte, offset int) (int, error) {
	packet := buf[offset:]
	if len(packet) == 0 {
		return 0, nil
	}

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	switch packet[0] >> 4 {
	case 4:
		tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	case 6:
		tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
	}

	return len(packet), nil
}

// WriteNotify implements channel.Notification
func (tun *netTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

// Flush implements tun.Device
func (tun *netTun) Flush() error {
	return nil
}

// Close implements tun.Device
func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

// MTU implements tun.Device
func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

func convertToFullAddr(addr xnet.Address, port xnet.Port) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if addr.Family().IsIPv4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.IP()),
		Port: port.Value(),
	}, protoNumber
}

func (net *Net) DialContextTCP(ctx context.Context, addr xnet.Address, port xnet.Port) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr, port)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

func (net *Net) DialUDP(addr xnet.Address, port xnet.Port) (*gonet.UDPConn, error) {
	fa, pn := convertToFullAddr(addr, port)
	return gonet.DialUDP(net.stack, nil, &fa, pn)
}

func (n *Net) HasV4() bool {
	return n.hasV4
}

func (n *Net) HasV6() bool {
	return n.hasV6
}
