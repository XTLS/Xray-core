package shadowsocks

import (
	"context"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type testUDPAssociationDispatcher struct {
	routing.Dispatcher
	run func(net.Destination, *transport.Link) error
}

func (d testUDPAssociationDispatcher) DispatchLink(_ context.Context, dest net.Destination, link *transport.Link) error {
	return d.run(dest, link)
}

func TestEmptyShadowsocksUDPRequestSelectsInitialRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	server, peer := stdnet.Pipe()
	defer server.Close()
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	ctx = session.ContextWithInbound(ctx, &session.Inbound{})
	account, err := (&Account{Password: "local fixture", CipherType: CipherType_AES_128_GCM}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Account: account}
	s := &Server{validator: new(Validator)}
	if err := s.validator.Add(user); err != nil {
		t.Fatal(err)
	}
	a := net.UDPDestination(net.LocalHostIP, 10001)
	b := net.UDPDestination(net.LocalHostIP, 10002)
	routed := make(chan net.Destination, 1)
	result := make(chan error, 1)
	d := testUDPAssociationDispatcher{run: func(dest net.Destination, link *transport.Link) (err error) {
		defer func() { result <- err }()
		routed <- dest
		mb, err := link.Reader.ReadMultiBuffer()
		defer buf.ReleaseMulti(mb)
		if err != nil {
			return err
		}
		if len(mb) != 1 || string(mb[0].Bytes()) != "payload" || mb[0].UDP == nil || *mb[0].UDP != b {
			return errors.New("expected only the nonempty datagram with destination B")
		}
		return nil
	}}
	done := make(chan error, 1)
	go func() { done <- s.handleUDPPayload(ctx, server, d) }()
	defer func() {
		cancel()
		<-done
	}()
	send := func(dest net.Destination, data []byte) {
		t.Helper()
		packet, err := EncodeUDPPacket(&protocol.RequestHeader{User: user, Address: dest.Address, Port: dest.Port}, data)
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Release()
		if _, err := peer.Write(packet.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	send(a, nil)
	select {
	case dest := <-routed:
		if dest != a {
			t.Fatalf("empty first packet routed to %s, want %s", dest, a)
		}
	case <-ctx.Done():
		t.Fatal("packet selected no route")
	}
	send(b, []byte("payload"))
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("second packet did not reach selected route")
	}
}
