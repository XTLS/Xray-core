package scenarios

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestCoreDialUDPFirstPacketSelectsRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	listen := func() *net.UDPConn {
		t.Helper()
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: []byte{127, 0, 0, 1}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return peer
	}
	first, second, override := listen(), listen(), listen()
	allow := []*freedom.FirewallConfig{{Action: freedom.RuleAction_Allow}}
	instance, err := core.New(withDefaultApps(&core.Config{
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{Firewall: allow})},
			{Tag: "override", ProxySettings: serial.ToTypedMessage(&freedom.Config{
				Firewall: allow,
				DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(override.LocalAddr().(*net.UDPAddr).Port),
				}},
			})},
		},
		App: []*serial.TypedMessage{serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
			TargetTag: &router.RoutingRule_Tag{Tag: "override"},
			PortList: &net.PortList{Range: []*net.PortRange{
				net.SinglePortRange(net.Port(second.LocalAddr().(*net.UDPAddr).Port)),
			}},
		}}})},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer internet.InitSystemDialer(nil, nil)
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}

	open := func() net.PacketConn {
		t.Helper()
		conn, err := core.DialUDP(ctx, instance)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	exchange := func(conn net.PacketConn, target net.Addr, peer *net.UDPConn, wantSource net.Addr, message string) string {
		t.Helper()
		if n, err := conn.WriteTo([]byte(message), target); err != nil || n != len(message) {
			t.Fatalf("write took %d bytes: %v", n, err)
		}
		var data [32]byte
		n, sender, err := peer.ReadFromUDP(data[:])
		if err != nil || string(data[:n]) != message {
			t.Fatalf("peer received %q: %v", data[:n], err)
		}
		if _, err := peer.WriteToUDP(data[:n], sender); err != nil {
			t.Fatal(err)
		}
		n, src, err := conn.ReadFrom(data[:])
		if err != nil || src == nil || src.String() != wantSource.String() || string(data[:n]) != message {
			t.Fatalf("received %q from %v: %v", data[:n], src, err)
		}
		return sender.String()
	}
	conn := open()
	sender := exchange(conn, first.LocalAddr(), first, first.LocalAddr(), "first")
	if next := exchange(conn, second.LocalAddr(), second, second.LocalAddr(), "second"); next != sender {
		t.Fatalf("packet destination selected a new socket: %s, want %s", next, sender)
	}
	if next := exchange(conn, first.LocalAddr(), first, first.LocalAddr(), "back"); next != sender {
		t.Fatalf("first route was replaced: %s, want %s", next, sender)
	}
	fresh := open()
	exchange(fresh, second.LocalAddr(), override, second.LocalAddr(), "fresh")

	waiting := make(chan error, 1)
	go func() {
		var data [32]byte
		_, _, err := conn.ReadFrom(data[:])
		waiting <- err
	}()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiting:
		if err == nil {
			t.Fatal("closed packet socket returned another datagram")
		}
	case <-ctx.Done():
		t.Fatal("closing the packet socket did not wake ReadFrom")
	}
}
