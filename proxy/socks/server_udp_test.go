package socks

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type socksUDPTestDispatcher struct {
	routing.Dispatcher
	link func(context.Context, net.Destination, *transport.Link) error
}

func (d socksUDPTestDispatcher) DispatchLink(ctx context.Context, target net.Destination, link *transport.Link) error {
	return d.link(ctx, target, link)
}

func TestSocksUDPRouteReopensOnSameSocket(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	controlListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer controlListener.Close()
	peer, err := net.DialTCP("tcp4", nil, controlListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	control, err := controlListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	conn := NewTempUDPConn(listener, control, client.LocalAddr().(*net.UDPAddr))

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	stopClose := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopClose()
	defer conn.Close()

	first := net.UDPDestination(net.LocalHostIP, 10001)
	second := net.UDPDestination(net.LocalHostIP, 10002)
	calls := 0
	var retired *transport.Link
	checked := make(chan error, 2)
	dispatcher := socksUDPTestDispatcher{link: func(_ context.Context, target net.Destination, link *transport.Link) (err error) {
		defer func() {
			select {
			case checked <- err:
			case <-ctx.Done():
			}
		}()
		if target != first {
			return fmt.Errorf("route target %v, want the initial %v", target, first)
		}
		calls++
		switch calls {
		case 1:
			retired = link
		case 2:
			// A deferred Close of the old output must leave the new route
			// and its socket output alone.
			if err := common.Close(retired.Writer); err != nil {
				return err
			}
		default:
			return errors.New("unexpected new route")
		}
		packets, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		if len(packets) != 1 || packets[0].UDP == nil {
			buf.ReleaseMulti(packets)
			return errors.New("expected exactly one UDP datagram")
		}
		want := first
		if calls == 2 {
			want = second
		}
		if *packets[0].UDP != want {
			buf.ReleaseMulti(packets)
			return errors.New("packet destination changed")
		}
		packets[0].UDP = nil // A response without its own source uses this leg's header.
		if err := link.Writer.WriteMultiBuffer(packets); err != nil {
			return err
		}

		if calls == 2 {
			packets, err = link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			if len(packets) != 1 || packets[0].UDP == nil || *packets[0].UDP != first {
				buf.ReleaseMulti(packets)
				return errors.New("unexpected destination after reopening")
			}
			if err := link.Writer.WriteMultiBuffer(packets); err != nil {
				return err
			}
		}

		reader := link.Reader.(buf.TimeoutReader)
		packets, err = reader.ReadMultiBufferTimeout(20 * time.Millisecond)
		buf.ReleaseMulti(packets)
		if !errors.Is(err, buf.ErrReadTimeout) {
			return fmt.Errorf("timed read = %v", err)
		}
		return common.Close(link.Writer)
	}}

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- (&Server{}).handleUDPPayload(ctx, conn, dispatcher)
	}()
	for i, dest := range []net.Destination{first, second, first} {
		payload := []byte("reply without source")
		request, err := EncodeUDPPacket(&protocol.RequestHeader{Address: dest.Address, Port: dest.Port}, payload)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Write(request.Bytes())
		request.Release()
		if err != nil {
			t.Fatal(err)
		}
		response, err := buf.ReadBuffer(client)
		if err != nil {
			t.Fatal(err)
		}
		header, err := DecodeUDPPacket(response)
		if err != nil || header.Destination() != dest || string(response.Bytes()) != string(payload) {
			response.Release()
			t.Fatalf("reply header = %v, err = %v, want %v", header, err, dest)
		}
		response.Release()
		if i == 1 {
			continue
		}
		select {
		case err := <-checked:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("route did not retire")
		}
	}

	cancel()
	conn.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("association did not stop")
	}
}
